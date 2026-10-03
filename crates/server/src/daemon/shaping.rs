use super::{
    check_tun_worker, find_session_by_address, is_recoverable, record_downloads, send_server_batch,
    Arc, Instant, LinuxTun, MultiHeaders, Mutex, PacketDevice, RuntimeSession, ServerDaemonError,
    SessionMap, UdpSocket, UDP_BATCH_SIZE, UDP_DROP_LOG_INTERVAL, WORKER_HEALTH_POLL,
};
use crate::fair_queue::FairQueue;
use std::sync::Condvar;
use std::{io, sync::mpsc, thread};

pub(super) enum Destination {
    Internet,
    Client,
}

pub(super) struct PendingPacket {
    pub session: Arc<RuntimeSession>,
    pub destination: Destination,
    pub bytes: Vec<u8>,
    pub payload_len: usize,
}

struct State {
    queue: FairQueue<PendingPacket>,
    stopping: bool,
}
struct Shared {
    state: Mutex<State>,
    changed: Condvar,
}

#[derive(Clone)]
pub(super) struct QueueHandle(Arc<Shared>);

impl QueueHandle {
    pub(super) fn enqueue(&self, packet: PendingPacket, cost: usize) {
        if let Ok(mut state) = self.0.state.lock() {
            if state.stopping {
                return;
            }
            let was_empty = state.queue.is_empty();
            state.queue.enqueue(
                Arc::clone(&packet.session.traffic_group),
                packet,
                cost,
                Instant::now(),
            );
            if was_empty {
                self.0.changed.notify_one();
            }
        }
    }
}

pub(super) struct Worker {
    shared: Arc<Shared>,
    failures: mpsc::Receiver<io::Error>,
    thread: Option<thread::JoinHandle<()>>,
}

impl Worker {
    pub(super) fn check(&self) -> Result<(), ServerDaemonError> {
        check_tun_worker(&self.failures)
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        if let Ok(mut state) = self.shared.state.lock() {
            state.stopping = true;
        }
        self.shared.changed.notify_all();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

pub(super) fn start(
    bandwidth_mbps: u32,
    tun: Arc<LinuxTun>,
    socket: UdpSocket,
    sessions: SessionMap,
) -> (QueueHandle, Worker) {
    let shared = Arc::new(Shared {
        state: Mutex::new(State {
            queue: FairQueue::new(bandwidth_mbps, Instant::now()),
            stopping: false,
        }),
        changed: Condvar::new(),
    });
    let queue = QueueHandle(Arc::clone(&shared));
    let running = Arc::clone(&shared);
    let (failure, failures) = mpsc::sync_channel(1);
    let thread = thread::spawn(move || {
        if let Err(error) = run(&running, &tun, &socket, &sessions) {
            let _ = failure.send(error);
        }
    });
    (
        queue,
        Worker {
            shared,
            failures,
            thread: Some(thread),
        },
    )
}

fn poisoned() -> io::Error {
    io::Error::other("fair queue lock is poisoned")
}

fn run(
    shared: &Shared,
    tun: &LinuxTun,
    socket: &UdpSocket,
    sessions: &SessionMap,
) -> io::Result<()> {
    let mut ready = Vec::with_capacity(UDP_BATCH_SIZE);
    let mut datagrams = Vec::with_capacity(UDP_BATCH_SIZE);
    let mut peers = Vec::with_capacity(UDP_BATCH_SIZE);
    let mut counters = Vec::with_capacity(UDP_BATCH_SIZE);
    let mut lengths = Vec::with_capacity(UDP_BATCH_SIZE);
    let mut headers = MultiHeaders::preallocate(UDP_BATCH_SIZE, None);
    let mut drops = 0_u64;
    let mut last_report = Instant::now();
    loop {
        let mut state = shared.state.lock().map_err(|_| poisoned())?;
        if state.stopping {
            return Ok(());
        }
        let delay = loop {
            let (packet, delay) = state.queue.dequeue(Instant::now());
            if let Some(packet) = packet {
                ready.push(packet);
                if ready.len() < UDP_BATCH_SIZE {
                    continue;
                }
            }
            break delay;
        };
        if last_report.elapsed() >= UDP_DROP_LOG_INTERVAL {
            let total = state.queue.dropped.saturating_add(drops);
            if total > 0 {
                eprintln!("MouseVPN fair queue dropped {total} packets");
            }
            last_report = Instant::now();
        }
        if ready.is_empty() {
            // Wake periodically for health reporting; a producer also wakes us
            // immediately when the queue transitions from idle to active.
            let wait = delay.unwrap_or(WORKER_HEALTH_POLL);
            drop(
                shared
                    .changed
                    .wait_timeout(state, wait)
                    .map_err(|_| poisoned())?,
            );
            continue;
        }
        drop(state);
        for packet in ready.drain(..) {
            // Revoked or replaced sessions must not leak their queued traffic.
            if !is_current(&packet.session, sessions) {
                continue;
            }
            match packet.destination {
                Destination::Internet => match tun.send(&packet.bytes) {
                    Ok(()) => packet.session.traffic.add_upload(packet.payload_len as u64),
                    Err(error) if is_recoverable(&error) => drops = drops.saturating_add(1),
                    Err(error) => return Err(error),
                },
                Destination::Client => {
                    let Some(peer) = packet.session.peer() else {
                        continue;
                    };
                    datagrams.push(packet.bytes);
                    peers.push(peer);
                    counters.push(Arc::clone(&packet.session.traffic));
                    lengths.push(packet.payload_len as u64);
                }
            }
        }
        if !datagrams.is_empty() {
            let sent =
                send_server_batch(socket, &mut headers, &datagrams, &peers, datagrams.len())?;
            record_downloads(sent, &counters, &lengths);
            drops = drops.saturating_add((datagrams.len() - sent) as u64);
        }
        datagrams.clear();
        peers.clear();
        counters.clear();
        lengths.clear();
    }
}

fn is_current(session: &Arc<RuntimeSession>, sessions: &SessionMap) -> bool {
    session.authorization.is_active()
        && find_session_by_address(sessions, session.client_address)
            .is_some_and(|current| Arc::ptr_eq(&current, session))
}
