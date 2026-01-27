use crate::types::Decision;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

/// Stored decision info
#[derive(Debug, Clone)]
pub struct StoredDecision {
    pub id: i64,
    pub decision_type: String,
    pub scenario: Option<String>,
}

/// Thread-safe store for CrowdSec decisions
#[derive(Debug, Clone)]
pub struct DecisionStore {
    /// Map from IP address to decision info
    decisions: Arc<RwLock<HashMap<IpAddr, StoredDecision>>>,
    /// Reverse map from decision ID to IP for efficient deletion
    id_to_ip: Arc<RwLock<HashMap<i64, IpAddr>>>,
}

impl Default for DecisionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl DecisionStore {
    /// Create a new empty decision store
    pub fn new() -> Self {
        Self {
            decisions: Arc::new(RwLock::new(HashMap::new())),
            id_to_ip: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Check if an IP is banned
    pub fn is_banned(&self, ip: &IpAddr) -> bool {
        let decisions = self.decisions.read();
        if let Some(stored) = decisions.get(ip) {
            return stored.decision_type.eq_ignore_ascii_case("ban");
        }
        false
    }

    /// Get decision info for an IP if it exists
    pub fn get_decision(&self, ip: &IpAddr) -> Option<StoredDecision> {
        self.decisions.read().get(ip).cloned()
    }

    /// Add a decision to the store
    pub fn add_decision(&self, decision: &Decision) {
        // Only handle IP scope decisions for now
        if let Some(ip) = decision.get_ip() {
            if let Some(id) = decision.id {
                let stored = StoredDecision {
                    id,
                    decision_type: decision.decision_type.clone(),
                    scenario: decision.scenario.clone(),
                };

                let mut decisions = self.decisions.write();
                let mut id_map = self.id_to_ip.write();

                decisions.insert(ip, stored);
                id_map.insert(id, ip);
            }
        }
    }

    /// Remove a decision from the store by ID
    pub fn remove_decision(&self, decision: &Decision) {
        if let Some(id) = decision.id {
            let mut decisions = self.decisions.write();
            let mut id_map = self.id_to_ip.write();

            if let Some(ip) = id_map.remove(&id) {
                decisions.remove(&ip);
            }
        }
    }

    /// Apply a stream response: add new decisions and remove deleted ones
    pub fn apply_stream_response(&self, new: Vec<Decision>, deleted: Vec<Decision>) {
        // Process deletions first
        for decision in &deleted {
            self.remove_decision(decision);
        }

        // Then add new decisions (only ban type for now)
        for decision in &new {
            if decision.is_ban() {
                self.add_decision(decision);
            }
        }
    }

    /// Get the number of stored decisions
    pub fn len(&self) -> usize {
        self.decisions.read().len()
    }

    /// Check if the store is empty
    pub fn is_empty(&self) -> bool {
        self.decisions.read().is_empty()
    }

    /// Clear all decisions (for testing or reset)
    pub fn clear(&self) {
        self.decisions.write().clear();
        self.id_to_ip.write().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Decision;

    fn make_ban_decision(id: i64, ip: &str) -> Decision {
        Decision {
            id: Some(id),
            origin: Some("crowdsec".to_string()),
            decision_type: "ban".to_string(),
            scope: Some("ip".to_string()),
            value: Some(ip.to_string()),
            duration: Some("1h".to_string()),
            scenario: Some("test/scenario".to_string()),
            until: None,
            simulated: None,
            uuid: None,
        }
    }

    #[test]
    fn test_add_and_check_banned() {
        let store = DecisionStore::new();
        let decision = make_ban_decision(1, "192.168.1.100");

        assert!(!store.is_banned(&"192.168.1.100".parse().unwrap()));

        store.add_decision(&decision);

        assert!(store.is_banned(&"192.168.1.100".parse().unwrap()));
        assert!(!store.is_banned(&"192.168.1.101".parse().unwrap()));
    }

    #[test]
    fn test_remove_decision() {
        let store = DecisionStore::new();
        let decision = make_ban_decision(42, "10.0.0.1");

        store.add_decision(&decision);
        assert!(store.is_banned(&"10.0.0.1".parse().unwrap()));

        store.remove_decision(&decision);
        assert!(!store.is_banned(&"10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn test_apply_stream_response() {
        let store = DecisionStore::new();

        // Initial state: add some bans
        let new = vec![
            make_ban_decision(1, "1.2.3.4"),
            make_ban_decision(2, "5.6.7.8"),
        ];
        store.apply_stream_response(new, vec![]);

        assert!(store.is_banned(&"1.2.3.4".parse().unwrap()));
        assert!(store.is_banned(&"5.6.7.8".parse().unwrap()));
        assert_eq!(store.len(), 2);

        // Update: delete one, add another
        let new = vec![make_ban_decision(3, "9.10.11.12")];
        let deleted = vec![make_ban_decision(1, "1.2.3.4")];
        store.apply_stream_response(new, deleted);

        assert!(!store.is_banned(&"1.2.3.4".parse().unwrap()));
        assert!(store.is_banned(&"5.6.7.8".parse().unwrap()));
        assert!(store.is_banned(&"9.10.11.12".parse().unwrap()));
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn test_concurrent_access() {
        use std::thread;

        let store = DecisionStore::new();
        let store_clone = store.clone();

        // Writer thread
        let writer = thread::spawn(move || {
            for i in 0..100 {
                let ip = format!("10.0.0.{}", i % 256);
                let decision = make_ban_decision(i, &ip);
                store_clone.add_decision(&decision);
            }
        });

        // Reader thread
        let store_clone2 = store.clone();
        let reader = thread::spawn(move || {
            for _ in 0..100 {
                let _ = store_clone2.is_banned(&"10.0.0.1".parse().unwrap());
                let _ = store_clone2.len();
            }
        });

        writer.join().unwrap();
        reader.join().unwrap();

        // Should have completed without panicking
        assert!(store.len() > 0);
    }
}
