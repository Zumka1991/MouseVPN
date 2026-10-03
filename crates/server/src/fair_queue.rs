//! Byte-fair DRR queues under one token bucket, shared by both directions.
//! Time is supplied by the caller so overload and pacing are deterministic in tests.
use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::{Duration, Instant},
};

const QUANTUM: usize = 1_500;
const MAX_PACKET: usize = 65_535 + 48;
const MIN_CHARGE: usize = 256;
const GROUP_LIMIT: usize = 256 * 1024;
const TOTAL_LIMIT: usize = 16 * 1024 * 1024;
const MAX_AGE: Duration = Duration::from_millis(100);
const NANOS: u128 = 1_000_000_000;

struct Packet<T> {
    value: T,
    cost: usize,
    queued: Instant,
}

struct Group<T> {
    packets: VecDeque<Packet<T>>,
    deficit: usize,
    bytes: usize,
}

pub(crate) struct FairQueue<T> {
    groups: HashMap<Arc<str>, Group<T>>,
    active: VecDeque<Arc<str>>,
    bytes: usize,
    group_limit: usize,
    total_limit: usize,
    rate: u128,
    capacity: u128,
    tokens: u128,
    updated: Instant,
    pub(crate) dropped: u64,
}

impl<T> FairQueue<T> {
    pub(crate) fn is_empty(&self) -> bool {
        self.active.is_empty()
    }

    pub(crate) fn new(bandwidth_mbps: u32, now: Instant) -> Self {
        assert!(bandwidth_mbps > 0);
        let rate = u128::from(bandwidth_mbps) * 125_000;
        // At most 1ms of catch-up credit, or one maximum wire datagram.
        let capacity = (rate / 1_000).max(MAX_PACKET as u128) * NANOS;
        Self {
            groups: HashMap::new(),
            active: VecDeque::new(),
            bytes: 0,
            group_limit: GROUP_LIMIT,
            total_limit: TOTAL_LIMIT,
            rate,
            capacity,
            tokens: capacity,
            updated: now,
            dropped: 0,
        }
    }

    pub(crate) fn enqueue(&mut self, key: Arc<str>, value: T, cost: usize, now: Instant) -> bool {
        if cost == 0 || cost > MAX_PACKET {
            self.dropped = self.dropped.saturating_add(1);
            return false;
        }
        self.expire(&key, now);
        let charge = cost.max(MIN_CHARGE);
        if self
            .groups
            .get(&key)
            .is_some_and(|group| group.bytes + charge > self.group_limit)
        {
            self.dropped = self.dropped.saturating_add(1);
            return false;
        }
        // A full global queue must still admit a newly active account. Reclaim
        // space from the largest backlog instead of letting it exclude others.
        while self.bytes + charge > self.total_limit {
            let Some(largest) = self
                .groups
                .iter()
                .max_by_key(|(_, group)| group.bytes)
                .map(|(key, _)| Arc::clone(key))
            else {
                return false;
            };
            self.discard(&largest, true);
        }
        let group = self.groups.entry(Arc::clone(&key)).or_insert_with(|| {
            self.active.push_back(key);
            Group {
                packets: VecDeque::new(),
                deficit: QUANTUM,
                bytes: 0,
            }
        });
        group.packets.push_back(Packet {
            value,
            cost,
            queued: now,
        });
        group.bytes += charge;
        self.bytes += charge;
        true
    }

    /// A packet, a pacing delay, or neither when the queue is empty.
    pub(crate) fn dequeue(&mut self, now: Instant) -> (Option<T>, Option<Duration>) {
        let elapsed = now.saturating_duration_since(self.updated).as_nanos();
        self.tokens = (self.tokens + elapsed.saturating_mul(self.rate)).min(self.capacity);
        self.updated = self.updated.max(now);
        loop {
            let Some(key) = self.active.front().cloned() else {
                return (None, None);
            };
            self.expire(&key, now);
            let Some(group) = self.groups.get_mut(&key) else {
                continue;
            };
            let cost = group
                .packets
                .front()
                .expect("active group has packets")
                .cost;
            if cost > group.deficit {
                group.deficit += QUANTUM;
                self.active.rotate_left(1);
                continue;
            }
            let required = cost as u128 * NANOS;
            if self.tokens < required {
                let nanos = (required - self.tokens).div_ceil(self.rate);
                return (
                    None,
                    Some(Duration::from_nanos(
                        u64::try_from(nanos).unwrap_or(u64::MAX),
                    )),
                );
            }
            self.tokens -= required;
            group.deficit -= cost;
            let packet = group.packets.pop_front().expect("active group has packets");
            group.bytes -= cost.max(MIN_CHARGE);
            self.bytes -= cost.max(MIN_CHARGE);
            if group.packets.is_empty() {
                self.groups.remove(&key);
                self.active.pop_front();
            }
            return (Some(packet.value), None);
        }
    }

    fn expire(&mut self, key: &Arc<str>, now: Instant) {
        while self
            .groups
            .get(key)
            .and_then(|group| group.packets.front())
            .is_some_and(|packet| now.saturating_duration_since(packet.queued) >= MAX_AGE)
        {
            self.discard(key, false);
        }
    }

    fn discard(&mut self, key: &Arc<str>, tail: bool) {
        let group = self.groups.get_mut(key).expect("queued group exists");
        let packet = if tail {
            group.packets.pop_back()
        } else {
            group.packets.pop_front()
        }
        .expect("queued group has packets");
        let charge = packet.cost.max(MIN_CHARGE);
        group.bytes -= charge;
        self.bytes -= charge;
        self.dropped = self.dropped.saturating_add(1);
        if group.packets.is_empty() {
            self.groups.remove(key);
            self.active.retain(|active| active != key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_bytes_despite_packet_size_or_number_of_devices() {
        let now = Instant::now();
        let mut queue = FairQueue::new(900, now);
        for _ in 0..100 {
            queue.enqueue("alice".into(), (0, 1_500), 1_500, now);
            // Two devices/directions of Bob share one account key.
            for _ in 0..5 {
                queue.enqueue("bob".into(), (1, 300), 300, now);
            }
        }
        let mut bytes = [0_usize; 2];
        while let (Some((owner, size)), _) = queue.dequeue(now) {
            bytes[owner] += size;
            assert!(bytes[0].abs_diff(bytes[1]) <= QUANTUM);
        }
        assert!(bytes.iter().all(|bytes| *bytes > 40_000));
    }

    #[test]
    fn solo_account_uses_capacity_and_second_account_gets_a_turn() {
        let now = Instant::now();
        let mut queue = FairQueue::new(900, now);
        for _ in 0..100 {
            queue.enqueue("alice".into(), 0, 1_000, now);
        }
        for _ in 0..40 {
            assert_eq!(queue.dequeue(now).0, Some(0));
        }
        queue.enqueue("bob".into(), 1, 1_000, now);
        assert!((0..3).any(|_| queue.dequeue(now).0 == Some(1)));
        while queue.dequeue(now).0.is_some() {}
        assert_eq!(queue.bytes, 0);
    }

    #[test]
    fn aggregate_rate_is_bounded_with_virtual_time_and_idle_credit_is_capped() {
        let start = Instant::now();
        let mut queue = FairQueue::new(8, start);
        let mut sent = 0_usize;
        for tick in 0..1_000 {
            let now = start + Duration::from_millis(tick);
            for owner in ["alice", "bob"] {
                for _ in 0..8 {
                    queue.enqueue(owner.into(), 1_000, 1_000, now);
                }
            }
            while let (Some(size), _) = queue.dequeue(now) {
                sent += size;
            }
            assert!(sent <= 1_000 * usize::try_from(tick).unwrap() + MAX_PACKET);
        }
        assert!(sent >= 990_000);
        let now = start + Duration::from_secs(3_600);
        for _ in 0..100 {
            queue.enqueue("new".into(), 1_000, 1_000, now);
        }
        let mut burst = 0;
        while queue.dequeue(now).0.is_some() {
            burst += 1_000;
        }
        assert!(burst <= MAX_PACKET);
        assert!(queue.dequeue(now).1.is_some());
    }

    #[test]
    fn overload_is_bounded_and_a_new_account_is_admitted() {
        let now = Instant::now();
        let mut queue = FairQueue::new(900, now);
        queue.group_limit = 4_096;
        queue.total_limit = 4_096;
        for _ in 0..10_000 {
            queue.enqueue("flood".into(), 0, 1, now);
        }
        assert_eq!(queue.bytes, 4_096);
        assert!(queue.enqueue("interactive".into(), 1, 1_500, now));
        assert!(queue.bytes <= 4_096);
        assert!((0..20).any(|_| queue.dequeue(now).0 == Some(1)));
        assert!(queue.dropped > 9_000);
    }

    #[test]
    fn stale_packets_and_inactive_accounts_are_removed() {
        let now = Instant::now();
        let mut queue = FairQueue::new(1, now);
        queue.enqueue("old".into(), 0, 1_000, now);
        assert_eq!(queue.dequeue(now + MAX_AGE), (None, None));
        assert!(queue.groups.is_empty());
        assert_eq!(queue.bytes, 0);
        assert_eq!(queue.dropped, 1);
        assert!(!queue.enqueue("bad".into(), 0, MAX_PACKET + 1, now));
    }

    #[test]
    fn low_demand_gets_what_it_needs_and_bulk_borrows_the_rest() {
        let start = Instant::now();
        let mut queue = FairQueue::new(8, start);
        let mut delivered = [0_usize; 2];
        for tick in 0..2_000 {
            let now = start + Duration::from_millis(tick);
            // 0.8 Mbit/s of interactive demand, 16 Mbit/s of bulk demand.
            queue.enqueue("interactive".into(), (0, 100), 100, now);
            queue.enqueue("bulk".into(), (1, 2_000), 2_000, now);
            while let (Some((owner, size)), _) = queue.dequeue(now) {
                delivered[owner] += size;
            }
        }
        assert!(delivered[0] >= 199_500, "{delivered:?}");
        assert!(delivered[1] >= 1_750_000, "{delivered:?}");
        assert!(delivered.iter().sum::<usize>() <= 2_000_000 + MAX_PACKET);
    }
}
