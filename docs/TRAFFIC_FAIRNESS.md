# Account traffic fairness

The server can share one aggregate bandwidth budget between active accounts.
Upload and download consume the same budget: on a VPN gateway both directions
also generate traffic on the physical NIC. A quiet account does not reserve a
fixed slice. With a 900 Mbit/s budget, a 20 Mbit/s account leaves roughly
880 Mbit/s for a busy account; two continuously backlogged accounts share
approximately equally. Rates include tunnel overhead, so application throughput
is lower.

Enable it in the server TOML, outside `[[clients]]`:

```toml
[traffic]
bandwidth_mbps = 900
```

900 is an example for a 1 Gbit/s link with 10% headroom, not a universal default.
Validate without opening sockets or creating TUN with `relay-agent --check-config /etc/relay-node/server.toml`.
The supported range is 1–100000 decimal Mbit/s. An absent `[traffic]` section
preserves the old unlimited path and emits a startup notice. Invalid limits and
unknown fields inside `[traffic]` fail validation. Changing the budget takes effect
on daemon restart.

## How it works

- A byte-based deficit round robin scheduler gives each backlogged account the
  same weight regardless of packet size, protocol, device count or direction.
  The algorithm follows the [DRR description in iproute2](https://man7.org/linux/man-pages/man8/tc-drr.8.html).
- A shared token bucket keeps the combined rate below the configured budget,
  allowing a burst of at most 1 ms of traffic or one maximum datagram. Idle time
  does not accumulate unlimited credit. Handshakes and authenticated keepalives
  bypass data queues so a bulk transfer cannot intentionally queue them behind
  its application traffic.
- Queues are bounded to 256 KiB per account and 16 MiB in total. Small packets
  cost at least 256 bytes of queue accounting to bound metadata memory too.
  Packets queued for 100 ms expire. At the global limit, the largest backlog
  yields space to new arrivals. These bounds intentionally permit drops during
  overload; TCP can then reduce its sending rate.
- Upload packets are authenticated before entering the queue. Download packets
  are encrypted before entering it, so actual encapsulation size is charged.
  Both directions are checked again for revocation or session replacement before
  transmission. Traffic counters advance only for successfully submitted packets.
- The controller includes `account_id` in node snapshots. The node groups all
  devices of that account, persists the group, and scopes it to the controller
  identity. Peers cannot select their own group. Legacy keys and snapshots from
  older controllers fall back to one group per device.

## Automatic measurement on a new node

Stage `bandwidth.py` alongside `bootstrap-node.py`. The bootstrap command now
defaults to `--bandwidth-mbps auto`: before installing anything it measures
download and upload, chooses 90% of the slower median, and saves the resulting
numeric budget in `server.toml`. An explicit `--bandwidth-mbps 900` skips the
measurement. A failed or highly inconsistent measurement aborts setup; it never
silently substitutes a guessed capacity.

For an existing node, run the helper explicitly during a quiet maintenance window:

```sh
python3 bandwidth.py --output traffic.toml
```

Review and merge the resulting `[traffic]` section into the existing configuration.
The helper only creates a new snippet and refuses to overwrite an existing file.
It prints sample measurements separately on stderr. The VPN daemon never starts
a speed test, including after a restart.

The default endpoints are the [Cloudflare speed test APIs](https://github.com/cloudflare/speedtest).
The test transfers about 382 MiB of synthetic bytes across two HTTPS connections;
it sends no VPN packets, keys or credentials. Custom compatible HTTPS endpoints
can be passed with `--download-url` and `--upload-url`. TLS validation is enabled.

This measures the tested route's currently available throughput, not a hosting
contract or an immutable link capacity. Other traffic, CPU limits and the test
endpoint can reduce the estimate. Virtual NIC speed is not used as a substitute.
Retest after capacity changes, or use the provider's known rate with headroom.

## Rollout and scope

Update the controller before the VPN nodes to enable grouping by account. Older
agents ignore the new field; newer agents accept older snapshots using the device
fallback. A live change in a device's account group invalidates its old session
so queued traffic cannot keep an obsolete share; clients reconnect normally.

The budget covers one daemon. If multiple VPN daemons or other busy services
share the same NIC, their budgets must fit the available capacity together.
They do not coordinate their token buckets or lend capacity across processes.
Queues inside the hosting provider and already-arriving UDP traffic cannot be
controlled by a userspace VPN scheduler. This is not an ingress flood defense.

## Verification

Run the normal tests with the toolchain in `rust-toolchain.toml`:

```sh
cargo test -p mousevpn-server -p mousevpn-config -p mousevpn-admin-api -p mousevpn-control-plane -p mousevpn-account-client
python3 -m unittest discover -s deploy/commercial -p 'test_bandwidth.py'
```

Scheduler tests use virtual time: unequal packet sizes, devices sharing an
account, idle capacity borrowing, low-demand traffic alongside bulk traffic,
aggregate rate, bounded idle credit, global/per-account pressure and stale queues.
Registry tests cover account identity, restart, ownership changes and revocation.

There is also an opt-in test with real Linux TUN, UDP, authenticated handshakes and
packet encryption in both directions for legacy, Morph and Speedy. It verifies
that revoked queued traffic is not emitted. Run it **only in a disposable network
namespace** with `CAP_NET_ADMIN` and `/dev/net/tun`, never directly in the host's
network namespace:

```sh
# First build the unit-test executable; Cargo prints its path.
cargo test -p mousevpn-server --lib --no-run
# Substitute the printed path below. The test network has no WAN access.
docker run --rm --network none --cap-add NET_ADMIN --device /dev/net/tun \
  --mount "type=bind,src=$PWD,dst=/workspace,readonly" \
  --entrypoint /workspace/target/debug/deps/mousevpn_server-<hash> \
  rust:1-slim-bookworm --ignored --nocapture shaped_packets_cross_real_tun
```

The deployed node budgets and the retirement of the former listeners are recorded
in [COMMERCIAL.md](COMMERCIAL.md#распределение-полосы-с-3-октября).

These tests verify behavior and isolation, not that a particular VPS can encrypt
1 Gbit/s. Production throughput and latency still depend on that node's CPU,
network and competing workloads.
