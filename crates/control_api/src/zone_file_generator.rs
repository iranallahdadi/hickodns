use anyhow::Context;
use std::sync::Arc;
use tokio_postgres::Client;
use std::path::Path;
use tokio::task;

fn ensure_trailing_dot(s: &str) -> String {
    if s.ends_with('.') { s.to_string() } else { format!("{}.", s) }
}

fn fqdn_for_record(name: &str, domain: &str) -> String {
    let domain_base = domain.trim_end_matches('.');
    if name == "@" {
        ensure_trailing_dot(domain_base)
    } else if name.ends_with('.') {
        name.to_string()
    } else {
        ensure_trailing_dot(&format!("{}.{}", name.trim_end_matches('.'), domain_base))
    }
}

pub async fn generate_all(base_dir: &str, db: Arc<Client>) -> anyhow::Result<()> {
    let base = base_dir.to_string();
    let db = db.clone();

    // do blocking FS work in a spawn_blocking
    task::spawn_blocking(move || -> anyhow::Result<()> {
        let base_path = Path::new(&base);
        std::fs::create_dir_all(base_path).with_context(|| format!("failed to create dir {}", base))?;

        // Open a new tokio runtime to run DB queries synchronously is awkward; instead,
        // we will use the existing client by blocking on a small separate runtime section.
        // But for simplicity, call out to the postgres client synchronously via blocking call
        // using a small tokio runtime here.
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;

        rt.block_on(async move {
            let zones = db
                .query("SELECT CAST(id AS varchar), domain FROM zones", &[])
                .await
                .unwrap_or_default();

            // build named.toml content
            let mut named = String::new();
            named.push_str("listen_addrs_ipv4 = [\"0.0.0.0\"]\n\n");

            for z in zones {
                let zone_id: String = z.try_get("id").unwrap_or_default();
                let domain: String = z.try_get("domain").unwrap_or_default();
                let zone_file_name = format!("zone.{}", domain.trim_end_matches('.'));
                let zone_path = base_path.join(&zone_file_name);

                // query records for this zone
                let recs = db
                    .query(
                        "SELECT name, type, value, ttl, priority FROM records WHERE zone_id = $1",
                        &[&zone_id],
                    )
                    .await
                    .unwrap_or_default();

                // write zone file
                let mut zone_contents = String::new();
                let domain_dot = ensure_trailing_dot(domain.trim_end_matches('.'));

                // prefer to write an SOA if present; otherwise synthesize a basic one
                let mut has_soa = false;
                for r in &recs {
                    let rtype: String = r.try_get("type").unwrap_or_default();
                    if rtype.to_uppercase() == "SOA" {
                        has_soa = true;
                        break;
                    }
                }

                if !has_soa {
                    // synthetic SOA: ns1.<domain> hostmaster.<domain> <serial> 3600 3600 604800 3600
                    let serial = chrono::Utc::now().format("%Y%m%d%H%M").to_string();
                    let soa_value = format!("ns1.{} hostmaster.{} {} 3600 3600 604800 3600", domain_dot, domain_dot, serial);
                    zone_contents.push_str(&format!("{} 3600 IN SOA {}\n", domain_dot, soa_value));
                }

                for r in recs {
                    let name: String = r.try_get("name").unwrap_or_default();
                    let rtype: String = r.try_get("type").unwrap_or_default();
                    let value: String = r.try_get("value").unwrap_or_default();
                    let ttl: i32 = r.try_get("ttl").unwrap_or(3600);
                    let priority: i32 = r.try_get("priority").unwrap_or(0);

                    let fqdn = fqdn_for_record(&name, &domain);

                    let mut out_value = value.clone();
                    if rtype.to_uppercase() == "MX" {
                        if priority > 0 && !value.split_whitespace().next().unwrap_or("").chars().all(|c| c.is_digit(10)) {
                            out_value = format!("{} {}", priority, value);
                        }
                    }

                    zone_contents.push_str(&format!("{} {} IN {} {}\n", fqdn, ttl, rtype, out_value));
                }

                std::fs::write(&zone_path, zone_contents).with_context(|| format!("failed to write zone file {:?}", zone_path))?;

                // append to named.toml
                named.push_str("[[zones]]\n");
                named.push_str(&format!("zone = \"{}\"\n", domain));
                named.push_str("zone_type = \"Primary\"\n\n");
                named.push_str("[[zones.stores]]\n");
                named.push_str("type = \"file\"\n");
                named.push_str(&format!("zone_path = \"{}\"\n\n", zone_path.to_string_lossy()));
            }

            // write named.toml
            let named_path = base_path.join("named.toml");
            std::fs::write(&named_path, named).with_context(|| format!("failed to write named.toml at {:?}", named_path))?;

            Ok(())
        })
    }).await??;

    Ok(())
}
