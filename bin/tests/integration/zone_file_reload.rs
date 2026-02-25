use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::str::FromStr;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use regex::Regex;
use tempfile::tempdir;

use hickory_net::{client::ClientHandle, xfer::Protocol};
use hickory_proto::rr::{Name, RecordType, rdata::A};

use crate::server_harness::{query_message};

// we need access to the generator - re-export from control_api crate
use control_api::zone_file_generator::{generate_from_data, RecordRow};

// small helper for building a simple zone dataset
fn make_zone(max_id: &str, domain: &str, records: Vec<RecordRow>) -> (Vec<(String,String)>, std::collections::HashMap<String, Vec<RecordRow>>) {
    let mut zones = Vec::new();
    zones.push((max_id.to_string(), domain.to_string()));
    let mut map = std::collections::HashMap::new();
    map.insert(max_id.to_string(), records);
    (zones, map)
}

#[tokio::test]
async fn reload_on_zonefile_change() {
    // temporary directory for config + zones
    let tmp = tempdir().unwrap();
    let zonedir = tmp.path().join("zones");
    std::fs::create_dir_all(&zonedir).unwrap();

    // first generation: example.com with www record
    let (zones, mut recs) = make_zone(
        "id1",
        "example.com",
        vec![RecordRow { name: "www".into(), rtype: "A".into(), value: "127.0.0.1".into(), ttl: 3600, priority: 0 }],
    );
    generate_from_data(zonedir.to_str().unwrap(), zones.clone(), recs.clone()).unwrap();

    // write minimal config pointing at our zonedir
    let conf_path = tmp.path().join("test.toml");
    let conf_contents = format!(
        "listen_addrs_ipv4 = [\"127.0.0.1\"]\ndirectory = \"{}\"\n",
        zonedir.to_string_lossy()
    );
    std::fs::write(&conf_path, conf_contents).unwrap();

    // spawn the server
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_hickory-dns"));
    cmd.stdout(Stdio::piped())
        .arg("-d")
        .arg(conf_path.to_str().unwrap())
        .arg("--zonedir")
        .arg(zonedir.to_str().unwrap())
        .arg("--port")
        .arg("0");

    let mut child = cmd.spawn().expect("failed to spawn server");
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    // parse listening port
    let addr_regex = Regex::new(r"listening for (UDP|TCP) on ((?:(?:0\.0\.0\.0)|(?:127\.0\.0\.1)|(?:\[::\])):\d+)").unwrap();
    let mut port = None;
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(10) {
        let mut line = String::new();
        if stdout.read_line(&mut line).unwrap_or(0) == 0 {
            continue;
        }
        if let Some(caps) = addr_regex.captures(&line) {
            let addr = caps.get(2).unwrap().as_str();
            if let Ok(sock) = SocketAddr::from_str(addr) {
                port = Some(sock.port());
                break;
            }
        }
    }
    let port = port.expect("server did not announce its port");

    // create a client to talk to the server
    let mut client = hickory_net::Client::new(("127.0.0.1", port)).expect("create client");

    // initial query should return 127.0.0.1
    let name = Name::from_str("www.example.com.").unwrap();
    let resp = query_message(&mut client, name.clone(), RecordType::A).await.unwrap();
    assert_eq!(resp.answers().len(), 1);
    if let A(address) = resp.answers()[0].data() {
        assert_eq!(address, &A::new(127, 0, 0, 1));
    } else {
        panic!("expected A record");
    }

    // modify zone adding foo record
    recs.get_mut("id1").unwrap().push(RecordRow { name: "foo".into(), rtype: "A".into(), value: "5.6.7.8".into(), ttl: 3600, priority: 0 });
    generate_from_data(zonedir.to_str().unwrap(), zones.clone(), recs.clone()).unwrap();

    // wait for reload (watcher sleeps 250ms internally)
    tokio::time::sleep(Duration::from_millis(500)).await;

    // query new record
    let resp2 = query_message(&mut client, Name::from_str("foo.example.com.").unwrap(), RecordType::A)
        .await
        .unwrap();
    assert_eq!(resp2.answers().len(), 1);
    if let A(address) = resp2.answers()[0].data() {
        assert_eq!(address, &A::new(5, 6, 7, 8));
    } else {
        panic!("expected foo A record");
    }

    // cleanup
    let _ = child.kill();
}
