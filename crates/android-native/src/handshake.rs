use std::{
    io,
    net::{SocketAddr, UdpSocket},
    sync::{atomic::AtomicBool, atomic::Ordering},
    thread,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Result};
use mousevpn_client_wire::ClientWire;
use mousevpn_config::ValidatedClientConfig;
use mousevpn_crypto::ClientHandshake;
use mousevpn_data_plane::TunnelDataPlane;
use mousevpn_protocol::{Datagram, Header, PacketKind, SessionParameters};
use mousevpn_transport::{DatagramTransport, UdpTransport};

/// Total time one connection attempt may spend before giving up.
const TIMEOUT: Duration = Duration::from_secs(10);
/// Gap between retransmissions of the initial message.
///
/// Mobile links drop handshake datagrams routinely, and sending the request
/// exactly once turned a single lost packet into a failed connect.
const RETRANSMIT: Duration = Duration::from_millis(700);

pub(crate) fn negotiate_cancellable(
    socket: UdpSocket,
    config: &ValidatedClientConfig,
    wire: &ClientWire,
    mut cancelled: impl FnMut() -> Result<bool>,
) -> Result<(UdpTransport, TunnelDataPlane, SessionParameters)> {
    negotiate_with_stop(socket, config, wire, &mut cancelled)
}

pub(crate) fn negotiate_interruptible(
    socket: UdpSocket,
    config: &ValidatedClientConfig,
    wire: &ClientWire,
    stopping: &AtomicBool,
) -> Result<(UdpTransport, TunnelDataPlane, SessionParameters)> {
    negotiate_with_stop(socket, config, wire, &mut || {
        Ok(stopping.load(Ordering::Relaxed))
    })
}

fn negotiate_with_stop(
    socket: UdpSocket,
    config: &ValidatedClientConfig,
    wire: &ClientWire,
    cancelled: &mut dyn FnMut() -> Result<bool>,
) -> Result<(UdpTransport, TunnelDataPlane, SessionParameters)> {
    socket
        .connect(config.server)
        .context("UDP connect failed")?;
    let mut transport = UdpTransport::from_socket(socket, config.server)?;
    let (plane, parameters) = renegotiate(&mut transport, config, wire, cancelled)?;
    Ok((transport, plane, parameters))
}

fn renegotiate(
    transport: &mut UdpTransport,
    config: &ValidatedClientConfig,
    wire: &ClientWire,
    cancelled: &mut dyn FnMut() -> Result<bool>,
) -> Result<(TunnelDataPlane, SessionParameters)> {
    let mut session_bytes = [0_u8; 8];
    getrandom::fill(&mut session_bytes).context("random generator failed")?;
    let session_id = u64::from_be_bytes(session_bytes);
    let mut handshake = ClientHandshake::new(
        &config.client_private_key,
        &config.server_public_key,
        &config.context,
    )?;
    let initial = handshake.write_initial(&[])?;
    // Retransmissions repeat these exact bytes, which the server recognises as a
    // duplicate and answers without replacing an already established session.
    let request = Datagram::new(
        Header {
            kind: PacketKind::HandshakeInit,
            flags: 0,
            session_id,
            sequence: 0,
        },
        &initial,
    )
    .encode();

    let started = Instant::now();
    let deadline = started + TIMEOUT;
    if cancelled()? {
        return Err(anyhow!("handshake cancelled"));
    }
    send_prelude(transport, wire)?;
    let mut encoded_request = Vec::new();
    send_request(transport, wire, &request, &mut encoded_request)?;
    let mut next_retransmit = started + RETRANSMIT;

    let mut buffer = vec![0_u8; 65_535];
    let mut decoded = Vec::with_capacity(65_535);
    loop {
        if cancelled()? {
            return Err(anyhow!("handshake cancelled"));
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(anyhow!("handshake timed out"));
        }
        if now >= next_retransmit {
            send_request(transport, wire, &request, &mut encoded_request)?;
            next_retransmit = now + RETRANSMIT;
        }

        let wait = next_retransmit
            .min(deadline)
            .saturating_duration_since(now)
            .min(Duration::from_millis(100));
        transport.set_read_timeout(Some(wait.max(Duration::from_millis(1))))?;
        let length = match transport.receive(&mut buffer) {
            Ok(length) => length,
            Err(error) if is_retryable(&error) => continue,
            Err(error) => return Err(error.into()),
        };
        let Ok(true) = wire.decode(&buffer[..length], &mut decoded) else {
            continue;
        };
        let Ok(response) = Datagram::decode(&decoded) else {
            continue;
        };
        if response.header.kind != PacketKind::HandshakeResponse
            || response.header.session_id != session_id
        {
            continue;
        }
        let (crypto, payload) = handshake.finish(response.payload)?;
        let parameters = SessionParameters::decode(&payload)?;
        if cancelled()? {
            return Err(anyhow!("handshake cancelled"));
        }
        return Ok((
            TunnelDataPlane::new(session_id, usize::from(parameters.mtu), crypto),
            parameters,
        ));
    }
}

fn send_request(
    transport: &mut UdpTransport,
    wire: &ClientWire,
    request: &[u8],
    encoded: &mut Vec<u8>,
) -> Result<()> {
    wire.encode(request, encoded)?;
    match transport.send(encoded) {
        // A refused or reset connection is a stale ICMP error from an earlier
        // datagram, not a reason to abandon this attempt.
        Ok(()) => Ok(()),
        Err(error) if is_retryable(&error) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn send_prelude(transport: &mut UdpTransport, wire: &ClientWire) -> Result<()> {
    let mut cover = Vec::new();
    for _ in 0..wire.cover_count()? {
        wire.encode_cover(&mut cover)?;
        transport.send(&cover)?;
        let jitter = wire.handshake_jitter_ms()?;
        if jitter != 0 {
            thread::sleep(Duration::from_millis(jitter));
        }
    }
    Ok(())
}

fn is_retryable(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::TimedOut
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::Interrupted
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::NotConnected
    )
}

pub(crate) fn bind_socket(server: SocketAddr) -> Result<UdpSocket> {
    let local = match server {
        SocketAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
        SocketAddr::V6(_) => SocketAddr::from(([0_u16; 8], 0)),
    };
    UdpSocket::bind(local).context("UDP bind failed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use mousevpn_config::{encode_public_key, encode_secret_key, ClientConfig, ClientProtocol};
    use mousevpn_crypto::KeyPair;

    #[test]
    fn cancellation_interrupts_a_silent_server_without_waiting_for_handshake_timeout() {
        // Keep the peer socket open so the client waits for a reply rather than ICMP.
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_keys = KeyPair::generate().unwrap();
        let client_keys = KeyPair::generate().unwrap();
        let config = ClientConfig {
            server: peer.local_addr().unwrap(),
            server_public_key: encode_public_key(&server_keys.public),
            client_private_key: encode_secret_key(&client_keys.secret),
            tun_name: "cancel-test".to_owned(),
            protocol: ClientProtocol::Legacy,
        }
        .validate()
        .unwrap();
        let wire = ClientWire::from_config(&config).unwrap();
        let started = Instant::now();
        let result =
            negotiate_cancellable(bind_socket(config.server).unwrap(), &config, &wire, || {
                Ok(started.elapsed() >= Duration::from_millis(200))
            });
        let Err(error) = result else {
            panic!("cancelled handshake completed")
        };
        assert!(error.to_string().contains("cancelled"));
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "cancellation waited for the handshake deadline"
        );
    }
}
