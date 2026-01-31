use maxminddb::Reader;
use std::net::IpAddr;

pub struct GeoDB {
    reader: Reader<Vec<u8>>,
}

impl GeoDB {
    pub fn open_from_bytes(bytes: Vec<u8>) -> Result<Self, maxminddb::MaxMindDBError> {
        let reader = Reader::from_source(bytes)?;
        Ok(Self { reader })
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
