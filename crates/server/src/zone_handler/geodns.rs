use std::net::IpAddr;
use std::sync::Arc;

use crate::proto::rr::{Name, LowerName, RData, RecordSet, RecordType};
use crate::zone_handler::{AuthLookup, LookupControlFlow, LookupOptions, ZoneHandler, ZoneType, AxfrPolicy};
use crate::server::RequestInfo;
use crate::zone_handler::auth_lookup::LookupRecords;

/// Zone handler that applies GeoDNS rules before falling through to other handlers.
///
/// The engine evaluates client IP and optional query context to determine a target
/// string.  Targets should be numeric IP addresses (A/AAAA) for now.
pub struct GeoZoneHandler {
    origin: LowerName,
    engine: geodns::GeoRuleEngine,
}

impl GeoZoneHandler {
    pub fn new(origin: Name, engine: geodns::GeoRuleEngine) -> Self {
        Self {
            origin: origin.into(),
            engine,
        }
    }
}

#[async_trait::async_trait]
impl ZoneHandler for GeoZoneHandler {
    fn zone_type(&self) -> ZoneType {
        ZoneType::Primary
    }

    fn axfr_policy(&self) -> AxfrPolicy {
        AxfrPolicy::Deny
    }

    fn origin(&self) -> &LowerName {
        &self.origin
    }

    async fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        request_info: Option<&RequestInfo<'_>>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        // only attempt geo routing for A/AAAA queries and when we know client ip
        if !(rtype == RecordType::A || rtype == RecordType::AAAA) {
            return LookupControlFlow::Skip;
        }
        let client_ip = if let Some(info) = request_info {
            info.src.ip()
        } else {
            return LookupControlFlow::Skip;
        };

        let name_str = name.to_string();
        let type_str = match rtype {
            RecordType::A => "A",
            RecordType::AAAA => "AAAA",
            _ => "",
        };

        if let Some(target) = self.engine.evaluate(client_ip, Some(&name_str), Some(type_str)) {
            // attempt to parse target as IP address
            if let Ok(addr) = target.parse::<IpAddr>() {
                let rdata = match addr {
                    IpAddr::V4(v4) => RData::A(v4.into()),
                    IpAddr::V6(v6) => RData::AAAA(v6.into()),
                };
                let mut rrset = RecordSet::with_ttl(Name::from(name.clone()), rtype, 300);
                rrset.add_rdata(rdata);
                let arc = Arc::new(rrset);
                let lookup = crate::zone_handler::auth_lookup::LookupRecords::new(lookup_options, arc);
                return LookupControlFlow::Break(Ok(AuthLookup::from(lookup)));
            }
            // if not an IP, ignore and fallthrough
        }

        LookupControlFlow::Skip
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::rr::Name;
    use crate::server::RequestInfo;
    use crate::zone_handler::LookupOptions;
    use std::net::SocketAddr;

    fn make_reqinfo(ip: &str) -> RequestInfo<'static> {
        RequestInfo::new(
            SocketAddr::new(ip.parse().unwrap(), 12345),
            crate::server::Protocol::Udp,
            &crate::proto::op::Header::new(0, crate::proto::op::MessageType::Query, crate::proto::op::OpCode::Query),
            &crate::proto::rr::LowerQuery::new(&Name::from_str("www.example.com.").unwrap(), RecordType::A, 1),
        )
    }

    #[test]
    fn test_geo_handler_skip_non_a() {
        let origin = Name::from_str("example.com.").unwrap();
        let engine = geodns::GeoRuleEngine::new(None);
        let handler = GeoZoneHandler::new(origin, engine);
        let info = make_reqinfo("1.2.3.4");
        let result = futures_util::executor::block_on(handler.lookup(&info.query.name.to_lowercase(), RecordType::NS, Some(&info), LookupOptions::default()));
        assert!(matches!(result, LookupControlFlow::Skip));
    }

    #[test]
    fn test_geo_handler_basic() {
        let origin = Name::from_str("example.com.").unwrap();
        let mut rule = geodns::GeoRule {
            id: "r1".into(),
            match_type: "country".into(),
            match_value: "US".into(),
            target: "1.1.1.1".into(),
            priority: 0,
            enabled: true,
            record_name: None,
            record_type: None,
        };
        let mut engine = geodns::GeoRuleEngine::new(None);
        engine.set_rules(vec![rule]);
        let handler = GeoZoneHandler::new(origin, engine);

        let info = make_reqinfo("1.2.3.4");
        // no match since geo DB not available
        let result = futures_util::executor::block_on(handler.lookup(&info.query.name.to_lowercase(), RecordType::A, Some(&info), LookupOptions::default()));
        assert!(matches!(result, LookupControlFlow::Skip));
    }
}
