use maxminddb::Reader;
use std::net::IpAddr;

pub struct GeoDB {
    reader: std::sync::Arc<Reader<Vec<u8>>>,
}

impl Clone for GeoDB {
    fn clone(&self) -> Self {
        Self {
            reader: self.reader.clone(),
        }
    }
}

impl GeoDB {
    pub fn open_from_bytes(bytes: Vec<u8>) -> Result<Self, maxminddb::MaxMindDBError> {
        let reader = Reader::from_source(bytes)?;
        Ok(Self {
            reader: std::sync::Arc::new(reader),
        })
    }

    pub fn country(&self, ip: IpAddr) -> Option<String> {
        if let Ok(country) = self.reader.lookup::<maxminddb::geoip2::Country>(ip) {
            if let Some(country) = country.country {
                return country.iso_code.map(|s| s.to_string());
            }
        }
        None
    }
}

/// GeoDNS rule for matching and routing based on geographic criteria.
#[derive(Clone, Debug)]
pub struct GeoRule {
    pub id: String,
    pub match_type: String,  // "country", "region", "continent", "default" or custom
    pub match_value: String, // e.g., "US", "EU" (ignored for "default")
    pub target: String,      // IP address or hostname to return
    pub priority: i32,       // higher values take precedence
    pub enabled: bool,       // rule disabled if false
    // optional record-level matching; if both are None the rule applies to whole zone
    pub record_name: Option<String>,
    pub record_type: Option<String>,
}

/// GeoRule engine: evaluates rules and returns best target based on client IP
pub struct GeoRuleEngine {
    rules: Vec<GeoRule>,
    db: Option<GeoDB>,
}

impl GeoRuleEngine {
    /// Create a new GeoRule engine, optionally with a GeoDB
    pub fn new(db: Option<GeoDB>) -> Self {
        Self {
            rules: Vec::new(),
            db,
        }
    }

    /// Add a rule to the engine
    pub fn add_rule(&mut self, rule: GeoRule) {
        self.rules.push(rule);
        // sort by priority descending so highest priority comes first
        self.rules.sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    /// Set all rules at once
    pub fn set_rules(&mut self, mut rules: Vec<GeoRule>) {
        // filter out disabled rules and sort by priority
        rules.retain(|r| r.enabled);
        rules.sort_by(|a, b| b.priority.cmp(&a.priority));
        self.rules = rules;
    }

    /// Evaluate rules for a client IP and return the target address
    /// Returns Some(target) if a rule matches, None if no match (use default)
    /// Evaluate rules for a client IP and optional query context (name/type).
    /// Returns Some(target) if a rule matches, None if no match (use default).
    pub fn evaluate(
        &self,
        client_ip: IpAddr,
        query_name: Option<&str>,
        query_type: Option<&str>,
    ) -> Option<String> {
        let country_opt = self.db.as_ref().and_then(|db| db.country(client_ip));
        
        // Helper closure to check match against rule and context
        let matches = |rule: &GeoRule| -> bool {
            if !rule.enabled {
                return false;
            }
            if let Some(qn) = query_name {
                if let Some(ref rn) = rule.record_name {
                    if !rn.eq_ignore_ascii_case(qn) {
                        return false;
                    }
                }
            }
            if let Some(qt) = query_type {
                if let Some(ref rt) = rule.record_type {
                    if !rt.eq_ignore_ascii_case(qt) {
                        return false;
                    }
                }
            }
            match rule.match_type.as_str() {
                "country" => {
                    if let Some(ref country) = country_opt {
                        return rule.match_value.eq_ignore_ascii_case(country);
                    }
                    false
                }
                "region" | "continent" => {
                    // treat value the same way for now
                    if let Some(ref country) = country_opt {
                        rule.match_value.eq_ignore_ascii_case(country)
                    } else {
                        false
                    }
                }
                "default" | "fallback" => {
                    // fallback rule always matches when reached
                    true
                }
                _ => false,
            }
        };
        
        // iterate rules in priority order; the list should already be sorted
        for rule in &self.rules {
            if matches(rule) {
                return Some(rule.target.clone());
            }
        }
        
        None // no rule or no default
    }

    /// Get all rules
    pub fn rules(&self) -> &[GeoRule] {
        &self.rules
    }
}

// ------------------------------------------------
// Unit tests for GeoDNS engine behavior
// ------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn make_rule(id: &str, mtype: &str, mval: &str, target: &str, priority: i32, enabled: bool) -> GeoRule {
        GeoRule {
            id: id.to_string(),
            match_type: mtype.to_string(),
            match_value: mval.to_string(),
            target: target.to_string(),
            priority,
            enabled,
            record_name: None,
            record_type: None,
        }
    }

    #[test]
    fn test_priority_ordering() {
        let mut engine = GeoRuleEngine::new(None);
        engine.add_rule(make_rule("r1", "country", "US", "1.1.1.1", 0, true));
        engine.add_rule(make_rule("r2", "country", "US", "2.2.2.2", 10, true));
        // rule with higher priority should come first
        assert_eq!(engine.rules()[0].id, "r2");
        assert_eq!(engine.rules()[1].id, "r1");
        let target = engine.evaluate("1.2.3.4".parse().unwrap(), None, None);
        assert_eq!(target.as_deref(), Some("2.2.2.2"));
    }

    #[test]
    fn test_disabled_rules_are_ignored() {
        let mut engine = GeoRuleEngine::new(None);
        engine.add_rule(make_rule("r1", "country", "US", "1.1.1.1", 0, false));
        engine.add_rule(make_rule("r2", "country", "US", "2.2.2.2", 0, true));
        let target = engine.evaluate("1.2.3.4".parse().unwrap(), None, None);
        assert_eq!(target.as_deref(), Some("2.2.2.2"));
    }

    #[test]
    fn test_fallback_rule() {
        let mut engine = GeoRuleEngine::new(None);
        engine.set_rules(vec![
            make_rule("r1", "default", "", "9.9.9.9", 0, true),
        ]);
        let target = engine.evaluate("10.0.0.1".parse().unwrap(), None, None);
        assert_eq!(target.as_deref(), Some("9.9.9.9"));
    }

    #[test]
    fn test_record_specific_matching() {
        let mut engine = GeoRuleEngine::new(None);
        let mut rule = make_rule("r1", "country", "US", "1.1.1.1", 0, true);
        rule.record_name = Some("www".to_string());
        rule.record_type = Some("A".to_string());
        engine.set_rules(vec![rule]);
        // when query name/type do not match, engine should yield None
        let target = engine.evaluate("1.2.3.4".parse().unwrap(), Some("other"), Some("A"));
        assert!(target.is_none());
        // with matching name and type
        let target2 = engine.evaluate("1.2.3.4".parse().unwrap(), Some("www"), Some("A"));
        assert_eq!(target2.as_deref(), Some("1.1.1.1"));
    }
}
