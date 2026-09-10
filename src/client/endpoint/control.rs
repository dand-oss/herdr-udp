use super::ClientEndpointId;

pub(crate) enum EndpointControlMessage {
    HealthPong,
    /// Local bridge hint: the transport path is recovering (`true`) or not.
    TransportRecovering(bool),
    /// Local bridge hint: the transport it is closing can be re-dialed on a
    /// credential that already carried a session, so the next reconnect
    /// costs no SSH and deserves tight pacing.
    TransportReconnectFast,
    Snapshot(Box<crate::protocol::ClientShellSnapshot>),
    Ignored,
}

pub(crate) fn decode_endpoint_control(
    kind: &str,
    data: &str,
) -> Result<EndpointControlMessage, String> {
    if kind == crate::protocol::endpoint::HEALTH_PONG_KIND {
        return Ok(EndpointControlMessage::HealthPong);
    }
    if kind == crate::protocol::endpoint::TRANSPORT_STATUS_KIND {
        #[derive(serde::Deserialize)]
        struct TransportStatus<'a> {
            state: &'a str,
        }
        let status: TransportStatus<'_> = serde_json::from_str(data)
            .map_err(|error| format!("invalid transport status: {error}"))?;
        return Ok(match status.state {
            "recovering" => EndpointControlMessage::TransportRecovering(true),
            "reconnect-fast" => EndpointControlMessage::TransportReconnectFast,
            _ => EndpointControlMessage::TransportRecovering(false),
        });
    }
    if kind == crate::protocol::endpoint::ENDPOINT_SNAPSHOT_KIND {
        let snapshot = serde_json::from_str(data)
            .map_err(|error| format!("invalid endpoint snapshot: {error}"))?;
        return Ok(EndpointControlMessage::Snapshot(Box::new(snapshot)));
    }
    if kind.starts_with("shell.snapshot.") {
        return Err(format!(
            "unsupported mandatory endpoint snapshot codec {kind:?}"
        ));
    }
    Ok(EndpointControlMessage::Ignored)
}

pub(crate) fn protocol_failure_is_fatal(endpoint_id: &ClientEndpointId) -> bool {
    endpoint_id.is_local()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::endpoint::ProfileId;

    #[test]
    fn unknown_optional_controls_are_ignored() {
        assert!(matches!(
            decode_endpoint_control("future.optional", "not json").unwrap(),
            EndpointControlMessage::Ignored
        ));
    }

    #[test]
    fn transport_status_reports_only_recovering_as_recovering() {
        for (state, recovering) in [("recovering", true), ("live", false)] {
            assert!(matches!(
                decode_endpoint_control(
                    crate::protocol::endpoint::TRANSPORT_STATUS_KIND,
                    &format!(r#"{{"state":"{state}"}}"#),
                )
                .unwrap(),
                EndpointControlMessage::TransportRecovering(value) if value == recovering
            ));
        }
        assert!(matches!(
            decode_endpoint_control(
                crate::protocol::endpoint::TRANSPORT_STATUS_KIND,
                r#"{"state":"reconnect-fast"}"#,
            )
            .unwrap(),
            EndpointControlMessage::TransportReconnectFast
        ));
        assert!(
            decode_endpoint_control(crate::protocol::endpoint::TRANSPORT_STATUS_KIND, "{}")
                .is_err()
        );
    }

    #[test]
    fn unknown_snapshot_codecs_are_rejected() {
        assert_eq!(
            decode_endpoint_control("shell.snapshot.v2", "{}")
                .err()
                .as_deref(),
            Some("unsupported mandatory endpoint snapshot codec \"shell.snapshot.v2\"")
        );
    }

    #[test]
    fn only_local_protocol_failures_end_the_client() {
        let remote =
            ClientEndpointId::Ssh(ProfileId::parse("0123456789abcdef0123456789abcdef").unwrap());
        assert!(protocol_failure_is_fatal(&ClientEndpointId::Local));
        assert!(!protocol_failure_is_fatal(&remote));
    }
}
