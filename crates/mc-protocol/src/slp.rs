//! Server List Ping response JSON, vanilla 1.8.9 field set and order.

use crate::{PROTOCOL_VERSION, VERSION_NAME};

pub fn status_json(motd: &str, online: u32, max: u32, players: &[String]) -> String {
    // A real server never reports more players than its max slots; a scanner
    // probing a busy VPN would otherwise see "online > max" and flag it.
    let online = online.min(max);
    // Byte-exact with vanilla/BungeeCord 1.8.9:
    // - "description" is a chat component OBJECT ({"text": ...}), not a string
    // - "sample" is omitted entirely when there are no players
    serde_json::json!({
        "version": { "name": VERSION_NAME, "protocol": PROTOCOL_VERSION },
        "players": players_json(online, max, players),
        "description": { "text": motd },
    })
    .to_string()
}

fn players_json(online: u32, max: u32, players: &[String]) -> serde_json::Value {
    if online == 0 || players.is_empty() {
        return serde_json::json!({ "max": max, "online": online });
    }
    // A busy server lists its players. Entries are the live roster when any
    // session is connected, otherwise per-boot decoys — never a fixed list,
    // which would be the same on every deployment (cross-server fingerprint).
    let n = (online as usize).min(players.len()).min(12);
    let sample: Vec<serde_json::Value> = players[..n]
        .iter()
        .map(|name| {
            serde_json::json!({
                "name": name,
                "id": crate::login_crypto::offline_uuid_string(name)
            })
        })
        .collect();
    serde_json::json!({ "max": max, "online": online, "sample": sample })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slp_golden() {
        let s = status_json("A Minecraft Server", 0, 20, &[]);
        assert_eq!(
            s,
            "{\"version\":{\"name\":\"1.8.9\",\"protocol\":47},\"players\":{\"max\":20,\"online\":0},\"description\":{\"text\":\"A Minecraft Server\"}}"
        );
    }

    #[test]
    fn online_never_exceeds_max() {
        let s = status_json("A Minecraft Server", 97, 20, &[]);
        assert!(s.contains("\"max\":20,\"online\":20"));
    }

    #[test]
    fn sample_lists_connected_players() {
        let s = status_json("A Minecraft Server", 5, 20, &["Notch".to_string()]);
        assert!(s.contains("\"sample\":[{\"name\":\"Notch\""), "{s}");
    }
}
