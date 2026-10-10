//! Connection slots, handed out by priority.
//!
//! A fetch needs two slots before it may connect: one of the fetcher-wide `global_slots`, and
//! one of its origin's (`h1_per_origin`, grown to `h2_per_origin` once the origin is seen
//! speaking HTTP/2 or HTTP/3). [`SlotPool`] holds both counts and the fetches waiting for them.
//!
//! Waiting fetches sit in the same four lanes as the scheduler's queues, and a freed slot goes
//! to the next waiter picked by the same weighted round-robin (High 8 : Normal 4 : Low 2 :
//! Idle 1 over a 15-step cycle, falling through to the other lanes when the preferred one has
//! nobody who can go). Priority is decided here, at the slots, because this is where fetches
//! actually wait: the run loop hands every request on as soon as it has coalesced it, so a
//! lane order applied only there is lost as soon as the slots are the bottleneck.
//!
//! A waiter whose origin is at its limit is passed over rather than blocking the waiters behind
//! it, and it holds no global slot while it waits: its turn comes when its origin has room.
//!
//! A fetch waits with the priority of the request that started it. A request that coalesces onto
//! a fetch already waiting does not change its place: a `High` request joining a waiting `Low`
//! fetch for the same resource waits as `Low`.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::sync::oneshot;
use url::Url;

use crate::net::fetcher::FetcherConfig;
use crate::net::types::Priority;

/// The global and per-origin connection slots of one fetcher, and who is waiting for them.
pub(crate) struct SlotPool {
    h1_per_origin: usize,
    h2_per_origin: usize,
    state: Mutex<State>,
}

struct State {
    global_free: usize,
    origins: HashMap<String, Origin>,
    /// Waiters per lane: High, Normal, Low, Idle.
    lanes: [VecDeque<Waiter>; 4],
    /// Position in the 15-step weighted round-robin cycle.
    turn: u8,
}

#[derive(Default)]
struct Origin {
    in_use: usize,
    h2: bool,
}

struct Waiter {
    origin: String,
    tx: oneshot::Sender<Slots>,
}

/// A place in line for slots, from [`SlotPool::enqueue`].
pub(crate) struct Ticket(oneshot::Receiver<Slots>);

impl Ticket {
    /// Waits until the pool hands this ticket its slots.
    ///
    /// `None` would mean the pool dropped the waiter without serving it, which it does not do
    /// while the ticket is alive; the caller treats it like a cancellation.
    pub(crate) async fn wait(self) -> Option<Slots> {
        self.0.await.ok()
    }
}

/// A global slot and an origin slot, given back to the pool when dropped.
pub(crate) struct Slots {
    pool: Arc<SlotPool>,
    origin: String,
    /// False once the slots were given back by hand, so drop does not give them back again.
    armed: bool,
}

impl Drop for Slots {
    fn drop(&mut self) {
        if self.armed {
            self.pool.release(&self.origin);
        }
    }
}

/// The lanes to try, in order, for each step of the 15-step cycle: the preferred lane first,
/// then the others. Matches [`Fetcher`](crate::net::fetcher::Fetcher)'s queue order.
fn lane_order(turn: u8) -> [usize; 4] {
    const HIGH: usize = 0;
    const NORMAL: usize = 1;
    const LOW: usize = 2;
    const IDLE: usize = 3;
    match turn {
        0..=7 => [HIGH, NORMAL, LOW, IDLE],
        8..=11 => [NORMAL, HIGH, LOW, IDLE],
        12..=13 => [LOW, NORMAL, HIGH, IDLE],
        _ => [IDLE, LOW, NORMAL, HIGH],
    }
}

fn lane(priority: Priority) -> usize {
    match priority {
        Priority::High => 0,
        Priority::Normal => 1,
        Priority::Low => 2,
        Priority::Idle => 3,
    }
}

/// The key slots are counted under: the URL's serialized origin.
pub(crate) fn origin_key(url: &Url) -> String {
    url.origin().ascii_serialization()
}

impl SlotPool {
    pub(crate) fn new(cfg: &FetcherConfig) -> Arc<Self> {
        Arc::new(Self {
            h1_per_origin: cfg.h1_per_origin,
            h2_per_origin: cfg.h2_per_origin,
            state: Mutex::new(State {
                global_free: cfg.global_slots,
                origins: HashMap::new(),
                lanes: Default::default(),
                turn: 0,
            }),
        })
    }

    fn limit(&self, origin: &Origin) -> usize {
        if origin.h2 {
            // Never below the h1 limit: the slots only ever grow.
            self.h2_per_origin.max(self.h1_per_origin)
        } else {
            self.h1_per_origin
        }
    }

    /// Joins the line for a global slot and a slot of `url`'s origin, behind any waiter of
    /// higher priority that can go, and behind earlier waiters of the same priority. Joining
    /// is synchronous, so a caller that enqueues in order keeps that order within a lane; the
    /// returned [`Ticket`] is then awaited for the slots. Dropping it gives up the place.
    pub(crate) fn enqueue(self: &Arc<Self>, url: &Url, priority: Priority) -> Ticket {
        let (tx, rx) = oneshot::channel();
        let mut state = self.state.lock();
        state.lanes[lane(priority)].push_back(Waiter {
            origin: origin_key(url),
            tx,
        });
        self.grant(&mut state);
        Ticket(rx)
    }

    /// [`enqueue`](Self::enqueue) and wait for the slots in one go.
    #[cfg(test)]
    pub(crate) async fn acquire(self: &Arc<Self>, url: &Url, priority: Priority) -> Option<Slots> {
        self.enqueue(url, priority).wait().await
    }

    /// Gives a fetch's slots back and hands them to whoever is next.
    fn release(self: &Arc<Self>, origin: &str) {
        let mut state = self.state.lock();
        state.global_free += 1;
        if let Some(o) = state.origins.get_mut(origin) {
            o.in_use -= 1;
        }
        self.grant(&mut state);
    }

    /// Hands out free slots to waiters, in lane order, until no waiter can go.
    fn grant(self: &Arc<Self>, state: &mut State) {
        // Waiters whose fetch gave up (cancelled, shut down) hold a closed channel.
        for lane in state.lanes.iter_mut() {
            lane.retain(|w| !w.tx.is_closed());
        }
        while state.global_free > 0 {
            let Some((lane, index)) = self.next_waiter(state) else {
                break;
            };
            let Some(waiter) = state.lanes[lane].remove(index) else {
                break;
            };
            state.turn = (state.turn + 1) % 15;
            state.global_free -= 1;
            state
                .origins
                .entry(waiter.origin.clone())
                .or_default()
                .in_use += 1;

            let slots = Slots {
                pool: self.clone(),
                origin: waiter.origin,
                armed: true,
            };
            if let Err(mut unsent) = waiter.tx.send(slots) {
                // The waiter gave up between the check above and now. Take the slots back
                // here: letting them drop would re-enter the lock this function runs under.
                unsent.armed = false;
                state.global_free += 1;
                if let Some(o) = state.origins.get_mut(&unsent.origin) {
                    o.in_use -= 1;
                }
            }
        }
    }

    /// The first waiter that can go, looking through the lanes in this turn's order.
    fn next_waiter(&self, state: &State) -> Option<(usize, usize)> {
        for lane in lane_order(state.turn) {
            let found = state.lanes[lane].iter().position(|w| {
                let origin = state.origins.get(&w.origin);
                let in_use = origin.map_or(0, |o| o.in_use);
                let limit = origin.map_or(self.h1_per_origin, |o| self.limit(o));
                in_use < limit
            });
            if let Some(index) = found {
                return Some((lane, index));
            }
        }
        None
    }

    /// Called with the HTTP version of every response: the first time an origin answers over
    /// HTTP/2 or HTTP/3, its limit grows to `h2_per_origin`, and waiters for it may go.
    pub(crate) fn observe(self: &Arc<Self>, url: &Url, version: http::Version) {
        if !matches!(version, http::Version::HTTP_2 | http::Version::HTTP_3) {
            return;
        }
        let mut state = self.state.lock();
        let origin = state.origins.entry(origin_key(url)).or_default();
        if !origin.h2 {
            origin.h2 = true;
            self.grant(&mut state);
        }
    }

    /// True once a response from this origin came in over HTTP/2 or HTTP/3.
    pub(crate) fn speaks_h2(&self, url: &Url) -> bool {
        self.state
            .lock()
            .origins
            .get(&origin_key(url))
            .is_some_and(|o| o.h2)
    }

    #[cfg(test)]
    pub(crate) fn limit_for(&self, url: &Url) -> usize {
        let state = self.state.lock();
        state
            .origins
            .get(&origin_key(url))
            .map_or(self.h1_per_origin, |o| self.limit(o))
    }

    #[cfg(test)]
    pub(crate) fn in_use(&self, url: &Url) -> usize {
        let state = self.state.lock();
        state.origins.get(&origin_key(url)).map_or(0, |o| o.in_use)
    }

    #[cfg(test)]
    pub(crate) fn global_free(&self) -> usize {
        self.state.lock().global_free
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn pool(global: usize, h1: usize, h2: usize) -> Arc<SlotPool> {
        SlotPool::new(&FetcherConfig {
            global_slots: global,
            h1_per_origin: h1,
            h2_per_origin: h2,
            ..FetcherConfig::default()
        })
    }

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    /// Queues `waiters`, in the order given, behind the pool's one slot, and returns their
    /// names in the order they got it. Joining the line is synchronous, so the order they wait
    /// in is exactly the order given; tasks only wait for their turn. Each one gives its slot
    /// back after reporting, so the next grant follows the report.
    async fn grant_order(
        pool: &Arc<SlotPool>,
        waiters: &[(&'static str, Priority, &str)],
    ) -> Vec<&'static str> {
        let blocker = pool
            .acquire(&url("https://blocker.example/"), Priority::High)
            .await;
        let (done_tx, mut done_rx) = tokio::sync::mpsc::unbounded_channel();
        for &(name, priority, u) in waiters {
            let ticket = pool.enqueue(&url(u), priority);
            let done_tx = done_tx.clone();
            tokio::spawn(async move {
                let slots = ticket.wait().await;
                done_tx.send(name).unwrap();
                drop(slots);
            });
        }
        drop(blocker);
        let mut order = Vec::new();
        for _ in waiters {
            order.push(done_rx.recv().await.unwrap());
        }
        order
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn high_goes_before_lower_lanes_already_waiting() {
        let p = pool(1, 6, 16);
        let order = grant_order(
            &p,
            &[
                ("low1", Priority::Low, "https://a.example/1"),
                ("low2", Priority::Low, "https://a.example/2"),
                ("idle", Priority::Idle, "https://a.example/3"),
                ("normal", Priority::Normal, "https://a.example/4"),
                ("high", Priority::High, "https://a.example/5"),
            ],
        )
        .await;
        assert_eq!(order[0], "high", "{order:?}");
        assert_eq!(order[1], "normal", "{order:?}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn same_lane_is_first_come_first_served() {
        let p = pool(1, 6, 16);
        let order = grant_order(
            &p,
            &[
                ("a", Priority::Normal, "https://a.example/1"),
                ("b", Priority::Normal, "https://a.example/2"),
                ("c", Priority::Normal, "https://a.example/3"),
            ],
        )
        .await;
        assert_eq!(order, ["a", "b", "c"]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn lower_lanes_are_not_starved() {
        // Twenty High waiters and one Low: Low must get a turn within one cycle of 15 grants,
        // not after every High.
        let p = pool(1, 32, 32);
        let mut waiters: Vec<(&'static str, Priority, &str)> = (0..20)
            .map(|_| ("high", Priority::High, "https://a.example/"))
            .collect();
        waiters.push(("low", Priority::Low, "https://a.example/"));
        let order = grant_order(&p, &waiters).await;
        let low_at = order.iter().position(|&n| n == "low").unwrap();
        assert!(low_at < 15, "low granted at {low_at}: {order:?}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn full_origin_does_not_block_other_origins() {
        // a.example is at its limit; a High waiter for it must not hold up a Low one for b.
        let p = pool(4, 1, 1);
        let a = url("https://a.example/");
        let held_a = p.acquire(&a, Priority::High).await;

        let high_a = tokio::spawn({
            let p = p.clone();
            let a = a.clone();
            async move { p.acquire(&a, Priority::High).await }
        });
        tokio::time::sleep(Duration::from_millis(10)).await;
        let low_b = tokio::time::timeout(
            Duration::from_millis(200),
            p.acquire(&url("https://b.example/"), Priority::Low),
        )
        .await;
        assert!(low_b.is_ok(), "a Low waiter for a free origin was held up");
        assert!(!high_a.is_finished());
        // While it waits for its origin, the High waiter holds no global slot.
        assert_eq!(p.global_free(), 2);

        drop(held_a);
        tokio::time::timeout(Duration::from_millis(200), high_a)
            .await
            .expect("waiter for a.example gets the freed origin slot")
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_cancelled_waiter_gives_up_its_place_and_leaks_nothing() {
        let p = pool(1, 6, 16);
        let a = url("https://a.example/");
        let held = p.acquire(&a, Priority::Normal).await;

        let gives_up = tokio::spawn({
            let (p, a) = (p.clone(), a.clone());
            async move { p.acquire(&a, Priority::High).await }
        });
        tokio::time::sleep(Duration::from_millis(10)).await;
        gives_up.abort();
        let _ = gives_up.await;

        drop(held);
        let next =
            tokio::time::timeout(Duration::from_millis(200), p.acquire(&a, Priority::Low)).await;
        assert!(next.is_ok(), "the slot went to the waiter that gave up");
        drop(next);
        assert_eq!(p.global_free(), 1);
        assert_eq!(p.in_use(&a), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn h2_growth_lets_waiters_for_that_origin_go() {
        let p = pool(32, 1, 3);
        let a = url("https://a.example/");
        let held = p.acquire(&a, Priority::Normal).await;
        let waiting = tokio::spawn({
            let (p, a) = (p.clone(), a.clone());
            async move { p.acquire(&a, Priority::Normal).await }
        });
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(!waiting.is_finished());

        p.observe(&a, http::Version::HTTP_2);
        let second = tokio::time::timeout(Duration::from_millis(200), waiting)
            .await
            .expect("growing the limit hands the new slots out")
            .unwrap();
        assert_eq!(p.limit_for(&a), 3);
        assert_eq!(p.in_use(&a), 2);
        drop((held, second));
        assert_eq!(p.in_use(&a), 0);
    }

    #[test]
    fn limits_start_at_h1_and_grow_once_per_origin() {
        let p = pool(32, 3, 8);
        let a = url("https://a.example/x");
        let b = url("https://b.example/x");
        let a_alt = url("https://a.example:8443/x");
        for u in [
            "http://example.com/",
            "https://example.com/",
            "ftp://example.com/",
        ] {
            assert_eq!(p.limit_for(&url(u)), 3, "{u}");
        }
        p.observe(&a, http::Version::HTTP_2);
        assert_eq!(p.limit_for(&a), 8);
        assert!(p.speaks_h2(&a));
        assert_eq!(p.limit_for(&b), 3);
        assert_eq!(p.limit_for(&a_alt), 3);
        // More h2 or h3 responses, or an h1 one, change nothing.
        p.observe(&a, http::Version::HTTP_3);
        p.observe(&a, http::Version::HTTP_11);
        assert_eq!(p.limit_for(&a), 8);
    }
}
