use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;
use hickory_server::server::Server;
use hickory_server::zone_handler::Catalog;
use hickory_server::store::in_memory::InMemoryZoneHandler;
use hickory_server::proto::rr::{Name, Record, RecordType, RData, RecordSet, rdata::SOA, RrKey};
use std::collections::BTreeMap;
use tokio::task::JoinHandle;
use hickory_server::zone_handler::ZoneType;
use hickory_server::zone_handler::AxfrPolicy;
use hickory_server::net::runtime::TokioRuntimeProvider;

pub struct DnsManager {
    inner: Arc<Mutex<HashMap<String, (JoinHandle<()>, tokio::sync::oneshot::Sender<()>)>>>,
}

impl DnsManager {
    pub fn new() -> Self {
        Self { inner: Arc::new(Mutex::new(HashMap::new())) }
    }

    pub async fn start_server(
        &self,
        id: &str,
        bind_addr: SocketAddr,
        db: Arc<tokio_postgres::Client>,
    ) -> anyhow::Result<()> {
        let mut catalog = Catalog::new();

        // load zones from database
        let zones = db
            .query("SELECT CAST(id AS varchar), domain FROM zones", &[])
            .await
            .map_err(|e| anyhow::anyhow!(e))?;

        for row in zones {
            let domain: String = row.try_get("domain").unwrap_or_default();
            let zone_id: String = row.try_get("id").unwrap_or_default();

                let origin: Name = match Name::from_ascii(&domain) {
                Ok(n) => n,
                Err(e) => {
                    tracing::warn!(%domain, "invalid zone domain, skipping: {}", e);
                    continue;
                }
            };

            let mut records_map: BTreeMap<RrKey, RecordSet> = BTreeMap::new();

            let recs = db
                .query(
                    "SELECT name, type, value, ttl, priority FROM records WHERE zone_id = $1",
                    &[&zone_id],
                )
                .await
                .unwrap_or_default();

            for r in recs {
                let name_raw: String = r.try_get("name").unwrap_or_default();
                let rtype_raw: String = r.try_get("type").unwrap_or_default();
                let value_raw: String = r.try_get("value").unwrap_or_default();
                let ttl: i32 = r.try_get("ttl").unwrap_or(3600);
                let _priority: Option<i32> = r.try_get("priority").ok();

                // resolve record name into a full Name
                let name: Name = if name_raw.trim() == "@" {
                    origin.clone()
                } else if name_raw.ends_with('.') {
                    match Name::from_ascii(&name_raw) {
                        Ok(n) => n,
                        Err(e) => {
                            tracing::warn!(%name_raw, %domain, "invalid record name, skipping: {}", e);
                            continue;
                        }
                    }
                } else {
                    // relative name, append origin
                    let fqdn = format!("{}.{}", name_raw.trim().trim_end_matches('.'), domain.trim_end_matches('.'));
                    match Name::from_ascii(&format!("{}.", fqdn)) {
                        Ok(n) => n,
                        Err(e) => {
                            tracing::warn!(%name_raw, %domain, "invalid relative record name, skipping: {}", e);
                            continue;
                        }
                    }
                };

                // parse record type
                let rtype = match rtype_raw.parse::<RecordType>() {
                    Ok(t) => t,
                    Err(e) => {
                        tracing::warn!(%rtype_raw, "unknown record type, skipping: {}", e);
                        continue;
                    }
                };

                // parse rdata for supported types
                use hickory_server::proto::rr::rdata::{A, AAAA, CNAME, NS, MX, TXT, SOA, SRV};
                use core::str::FromStr;

                let rdata = match rtype {
                    RecordType::A => match A::from_str(&value_raw) {
                        Ok(a) => Some(RData::A(a)),
                        Err(e) => {
                            tracing::warn!(%value_raw, "invalid A record value, skipping: {}", e);
                            None
                        }
                    },
                    RecordType::AAAA => match AAAA::from_str(&value_raw) {
                        Ok(a) => Some(RData::AAAA(a)),
                        Err(e) => {
                            tracing::warn!(%value_raw, "invalid AAAA record value, skipping: {}", e);
                            None
                        }
                    },
                    RecordType::CNAME => match Name::from_str(&value_raw) {
                        Ok(n) => Some(RData::CNAME(CNAME(n))),
                        Err(e) => {
                            tracing::warn!(%value_raw, "invalid CNAME target, skipping: {}", e);
                            None
                        }
                    },
                    RecordType::NS => match Name::from_str(&value_raw) {
                        Ok(n) => Some(RData::NS(NS(n))),
                        Err(e) => {
                            tracing::warn!(%value_raw, "invalid NS target, skipping: {}", e);
                            None
                        }
                    },
                    RecordType::MX => {
                        let parts: Vec<&str> = value_raw.split_whitespace().collect();
                        if parts.len() >= 2 {
                            if let Ok(pref) = parts[0].parse::<u16>() {
                                if let Ok(namev) = Name::from_str(parts[1]) {
                                    Some(RData::MX(MX::new(pref, namev)))
                                } else {
                                    tracing::warn!(%value_raw, "invalid MX exchange, skipping");
                                    None
                                }
                            } else {
                                tracing::warn!(%value_raw, "invalid MX preference, skipping");
                                None
                            }
                        } else {
                            tracing::warn!(%value_raw, "malformed MX value, skipping");
                            None
                        }
                    }
                    RecordType::TXT => Some(RData::TXT(TXT::new(vec![value_raw.clone()]))),
                    RecordType::SOA => {
                        // expect: mname rname serial refresh retry expire minimum
                        let parts: Vec<&str> = value_raw.split_whitespace().collect();
                        if parts.len() >= 7 {
                            if let (Ok(mname), Ok(rname), Ok(serial), Ok(refresh), Ok(retry), Ok(expire), Ok(minimum)) = (
                                Name::from_str(parts[0]),
                                Name::from_str(parts[1]),
                                parts[2].parse::<u32>(),
                                parts[3].parse::<i32>(),
                                parts[4].parse::<i32>(),
                                parts[5].parse::<i32>(),
                                parts[6].parse::<u32>(),
                            ) {
                                Some(RData::SOA(SOA::new(mname, rname, serial, refresh, retry, expire, minimum)))
                            } else {
                                tracing::warn!(%value_raw, "malformed SOA value, skipping");
                                None
                            }
                        } else {
                            tracing::warn!(%value_raw, "malformed SOA value, skipping");
                            None
                        }
                    }
                    RecordType::SRV => {
                        let parts: Vec<&str> = value_raw.split_whitespace().collect();
                        if parts.len() >= 4 {
                            if let (Ok(priority), Ok(weight), Ok(port), Ok(target)) = (
                                parts[0].parse::<u16>(),
                                parts[1].parse::<u16>(),
                                parts[2].parse::<u16>(),
                                Name::from_str(parts[3]),
                            ) {
                                Some(RData::SRV(SRV::new(priority, weight, port, target)))
                            } else {
                                tracing::warn!(%value_raw, "malformed SRV value, skipping");
                                None
                            }
                        } else {
                            tracing::warn!(%value_raw, "malformed SRV value, skipping");
                            None
                        }
                    }
                    _ => {
                        tracing::warn!(%rtype_raw, "unsupported record type for DB import, skipping");
                        None
                    }
                };

                if let Some(rdata) = rdata {
                    let ttl_u32 = ttl.max(0) as u32;
                    let rr_name = name.clone();
                    let key = RrKey::new(rr_name.clone().into(), rtype);

                    let rr_set = records_map.entry(key).or_insert_with(|| RecordSet::new(rr_name.clone(), rtype, ttl_u32));
                    rr_set.add_rdata(rdata);
                }
            }

            // ensure SOA exists for zone; InMemoryZoneHandler::new will check for SOA
            let zone = if records_map.is_empty() {
                InMemoryZoneHandler::<TokioRuntimeProvider>::empty(origin.clone(), ZoneType::Primary, AxfrPolicy::Deny, #[cfg(feature = "__dnssec")] None)
            } else {
                match InMemoryZoneHandler::<TokioRuntimeProvider>::new(origin.clone(), records_map, ZoneType::Primary, AxfrPolicy::Deny, #[cfg(feature = "__dnssec")] None) {
                    Ok(z) => z,
                    Err(e) => {
                        tracing::warn!(%domain, "failed to create zone handler from DB: {}", e);
                        InMemoryZoneHandler::<TokioRuntimeProvider>::empty(origin.clone(), ZoneType::Primary, AxfrPolicy::Deny, #[cfg(feature = "__dnssec")] None)
                    }
                }
            };

            catalog.upsert(origin.to_lowercase().into(), vec![std::sync::Arc::new(zone)]);
        }

        let mut server = Server::new(catalog);

        // bind UDP socket
        let udp = tokio::net::UdpSocket::bind(bind_addr).await?;
        server.register_socket(udp);

        // spawn server run-loop
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let handle = tokio::spawn(async move {
            // wait for shutdown signal
            let _ = rx.await;
            // graceful shutdown
            let _ = server.shutdown_gracefully().await;
        });

        self.inner.lock().await.insert(id.to_string(), (handle, tx));
        Ok(())
    }

    pub async fn stop_server(&self, id: &str) -> anyhow::Result<()> {
        if let Some((handle, tx)) = self.inner.lock().await.remove(id) {
            let _ = tx.send(());
            let _ = handle.await;
        }
        Ok(())
    }
}
