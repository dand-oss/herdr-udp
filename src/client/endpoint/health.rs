use std::time::{Duration, Instant};

pub(crate) const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
pub(super) const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(10);
/// Probe deadline while the endpoint's transport reports its path as
/// recovering (a QUIC connection riding out a blackhole or an address change).
/// Long enough to cover a tunnel. The transport gives up after its own
/// 150 s grace and closes the local socket, sending its reconnect hint first;
/// this deadline sits a slow-probe interval and change behind it so that
/// close, not this timer, is what ends the connection, and the hint is read.
/// It is still a backstop: a bridge that never closes cannot hold the
/// endpoint in this state indefinitely.
pub(crate) const ROAMING_GRACE: Duration = Duration::from_secs(160);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum HealthAction {
    None,
    Ping,
    Expired,
}

pub(super) struct EndpointHealth {
    connected_at: Instant,
    last_received: Instant,
    ping_sent_at: Option<Instant>,
    ready: bool,
    recovering: bool,
}

impl EndpointHealth {
    pub(super) fn new(now: Instant) -> Self {
        Self {
            connected_at: now,
            last_received: now,
            ping_sent_at: None,
            ready: false,
            recovering: false,
        }
    }

    /// The local transport says the path is recovering, not lost: keep the
    /// endpoint online and stretch the probe deadline to the roaming grace.
    pub(super) fn set_recovering(&mut self, recovering: bool) {
        self.recovering = recovering;
    }

    pub(super) fn received(&mut self, now: Instant) {
        self.last_received = now;
        self.ping_sent_at = None;
    }

    pub(super) fn ready(&mut self) {
        self.ready = true;
    }

    pub(super) fn action(&self, now: Instant) -> HealthAction {
        let initial_snapshot_expired =
            !self.ready && now.saturating_duration_since(self.connected_at) >= HEARTBEAT_TIMEOUT;
        let probe_timeout = if self.recovering {
            ROAMING_GRACE
        } else {
            HEARTBEAT_TIMEOUT
        };
        let probe_expired = self
            .ping_sent_at
            .is_some_and(|sent_at| now.saturating_duration_since(sent_at) >= probe_timeout);
        if initial_snapshot_expired || probe_expired {
            HealthAction::Expired
        } else if self.ping_sent_at.is_none()
            && now.saturating_duration_since(self.last_received) >= HEARTBEAT_INTERVAL
        {
            HealthAction::Ping
        } else {
            HealthAction::None
        }
    }

    pub(super) fn ping_sent(&mut self, now: Instant) {
        self.ping_sent_at = Some(now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quiet_connection_is_probed_then_expires_without_a_reply() {
        let now = Instant::now();
        let mut health = EndpointHealth::new(now);
        assert_eq!(health.action(now), HealthAction::None);
        assert_eq!(health.action(now + HEARTBEAT_INTERVAL), HealthAction::Ping);
        health.ping_sent(now + HEARTBEAT_INTERVAL);
        assert_eq!(
            health.action(now + HEARTBEAT_INTERVAL + HEARTBEAT_TIMEOUT),
            HealthAction::Expired
        );
    }

    #[test]
    fn any_incoming_message_satisfies_an_outstanding_probe() {
        let now = Instant::now();
        let mut health = EndpointHealth::new(now);
        health.ready();
        health.ping_sent(now);
        health.received(now + HEARTBEAT_TIMEOUT - Duration::from_millis(1));
        assert_eq!(health.action(now + HEARTBEAT_TIMEOUT), HealthAction::None);
    }

    #[test]
    fn a_recovering_path_stretches_the_probe_deadline_to_the_roaming_grace() {
        let now = Instant::now();
        let mut health = EndpointHealth::new(now);
        health.ready();
        health.set_recovering(true);
        health.ping_sent(now);
        assert_eq!(health.action(now + HEARTBEAT_TIMEOUT), HealthAction::None);
        assert_eq!(
            health.action(now + ROAMING_GRACE - Duration::from_millis(1)),
            HealthAction::None
        );
        assert_eq!(health.action(now + ROAMING_GRACE), HealthAction::Expired);

        health.set_recovering(false);
        assert_eq!(
            health.action(now + HEARTBEAT_TIMEOUT),
            HealthAction::Expired
        );
    }

    #[test]
    fn heartbeats_do_not_hide_a_missing_initial_snapshot() {
        let now = Instant::now();
        let mut health = EndpointHealth::new(now);
        health.ping_sent(now + HEARTBEAT_INTERVAL);
        health.received(now + HEARTBEAT_INTERVAL + Duration::from_secs(1));
        assert_eq!(
            health.action(now + HEARTBEAT_TIMEOUT),
            HealthAction::Expired
        );
    }
}
