/// Comprehensive validation for DNS records, zones, and configurations
use regex::Regex;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub struct ValidationError {
    pub field: String,
    pub message: String,
}

impl ValidationError {
    pub fn new(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            message: message.into(),
        }
    }
}

/// Validate a domain name for use as a DNS zone
pub fn validate_zone_domain(domain: &str) -> Result<(), ValidationError> {
    let domain = domain.trim();
    
    if domain.is_empty() {
        return Err(ValidationError::new("domain", "Domain must not be empty"));
    }
    
    if domain.len() > 253 {
        return Err(ValidationError::new("domain", "Domain exceeds 253 characters"));
    }
    
    if !domain.ends_with('.') {
        return Err(ValidationError::new("domain", "Domain must end with a period (.)"));
    }

    // Check each label in the domain
    let labels: Vec<&str> = domain.trim_end_matches('.').split('.').collect();
    if labels.is_empty() || labels.iter().all(|l| l.is_empty()) {
        return Err(ValidationError::new("domain", "Invalid domain format"));
    }

    for label in labels {
        if label.is_empty() {
            return Err(ValidationError::new("domain", "Labels cannot be empty"));
        }
        if label.len() > 63 {
            return Err(ValidationError::new("domain", "Domain labels cannot exceed 63 characters"));
        }
        if !label.chars().all(|c| c.is_alphanumeric() || c == '-') {
            return Err(ValidationError::new("domain", "Domain labels can only contain alphanumeric characters and hyphens"));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(ValidationError::new("domain", "Domain labels cannot start or end with a hyphen"));
        }
    }

    Ok(())
}

/// Validate a record name (can be @, subdomain, or wildcard)
pub fn validate_record_name(name: &str) -> Result<(), ValidationError> {
    if name == "@" || name == "*" {
        return Ok(());
    }

    let name_trimmed = name.trim_end_matches('.');
    if name_trimmed.is_empty() {
        return Err(ValidationError::new("name", "Record name cannot be empty (use '@' for zone apex)"));
    }

    // Simple validation for subdomain structure
    let labels: Vec<&str> = name_trimmed.split('.').collect();
    for label in labels {
        if label.is_empty() {
            return Err(ValidationError::new("name", "Invalid label structure"));
        }
        if label.len() > 63 {
            return Err(ValidationError::new("name", "Labels cannot exceed 63 characters"));
        }
        if !label.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '*') {
            return Err(ValidationError::new("name", "Invalid characters in label"));
        }
    }

    Ok(())
}

/// Validate TTL value
pub fn validate_ttl(ttl: u32) -> Result<(), ValidationError> {
    if ttl == 0 {
        return Err(ValidationError::new("ttl", "TTL must be greater than 0"));
    }
    if ttl > 2147483647 {
        return Err(ValidationError::new("ttl", "TTL exceeds maximum value (2147483647)"));
    }
    Ok(())
}

/// Validate an IPv4 address
pub fn validate_ipv4(addr: &str) -> Result<Ipv4Addr, ValidationError> {
    addr.trim().parse::<Ipv4Addr>()
        .map_err(|_| ValidationError::new("value", "Invalid IPv4 address"))
}

/// Validate an IPv6 address
pub fn validate_ipv6(addr: &str) -> Result<Ipv6Addr, ValidationError> {
    addr.trim().parse::<Ipv6Addr>()
        .map_err(|_| ValidationError::new("value", "Invalid IPv6 address"))
}

/// Validate a fully qualified domain name (must end with .)
pub fn validate_fqdn(fqdn: &str) -> Result<(), ValidationError> {
    let fqdn = fqdn.trim();
    
    if fqdn.is_empty() {
        return Err(ValidationError::new("value", "FQDN must not be empty"));
    }
    
    if !fqdn.ends_with('.') {
        return Err(ValidationError::new("value", "FQDN must end with a period (.)"));
    }

    // Basic label validation
    let labels: Vec<&str> = fqdn.trim_end_matches('.').split('.').collect();
    for label in labels {
        if label.is_empty() {
            return Err(ValidationError::new("value", "Invalid FQDN format"));
        }
        if label.len() > 63 {
            return Err(ValidationError::new("value", "FQDN labels cannot exceed 63 characters"));
        }
    }

    Ok(())
}

/// Validate MX record priority
pub fn validate_mx_priority(priority: i32) -> Result<(), ValidationError> {
    if priority < 0 || priority > 65535 {
        return Err(ValidationError::new("priority", "MX priority must be 0-65535"));
    }
    Ok(())
}

/// Validate SRV record format: "priority weight port target"
pub fn validate_srv_value(value: &str) -> Result<(), ValidationError> {
    let parts: Vec<&str> = value.trim().split_whitespace().collect();
    if parts.len() < 4 {
        return Err(ValidationError::new("value", "SRV record must have: priority weight port target"));
    }

    // Validate priority
    if let Err(_) = parts[0].parse::<u16>() {
        return Err(ValidationError::new("value", "SRV priority must be a number"));
    }

    // Validate weight
    if let Err(_) = parts[1].parse::<u16>() {
        return Err(ValidationError::new("value", "SRV weight must be a number"));
    }

    // Validate port
    if let Err(_) = parts[2].parse::<u16>() {
        return Err(ValidationError::new("value", "SRV port must be a number"));
    }

    // Validate target is FQDN
    validate_fqdn(parts[3])?;

    Ok(())
}

/// Validate CAA record format: "flags tag value"
pub fn validate_caa_value(value: &str) -> Result<(), ValidationError> {
    let parts: Vec<&str> = value.trim().split_whitespace().collect();
    if parts.len() < 2 {
        return Err(ValidationError::new("value", "CAA record must have: flags tag value"));
    }

    // Validate flags
    if let Err(_) = parts[0].parse::<u8>() {
        return Err(ValidationError::new("value", "CAA flags must be a number 0-255"));
    }

    Ok(())
}

/// Validate TXT record - check for proper quoting if needed
pub fn validate_txt_value(value: &str) -> Result<(), ValidationError> {
    if value.is_empty() {
        return Err(ValidationError::new("value", "TXT record value cannot be empty"));
    }
    
    // TXT records can contain quotes but need proper escaping
    // Allow mostly anything but provide a warning path for users
    Ok(())
}

/// Validate CNAME record - must be a single FQDN
pub fn validate_cname_value(value: &str) -> Result<(), ValidationError> {
    validate_fqdn(value)
}

/// Complete record value validation based on record type
pub fn validate_record_value(record_type: &str, value: &str) -> Result<(), ValidationError> {
    let rtype_upper = record_type.trim().to_uppercase();
    let value_trimmed = value.trim();

    if value_trimmed.is_empty() {
        return Err(ValidationError::new("value", "Record value cannot be empty"));
    }

    match rtype_upper.as_str() {
        "A" => {
            validate_ipv4(value_trimmed)?;
        }
        "AAAA" => {
            validate_ipv6(value_trimmed)?;
        }
        "CNAME" => {
            validate_cname_value(value_trimmed)?;
        }
        "MX" => {
            validate_fqdn(value_trimmed)?;
        }
        "NS" => {
            validate_fqdn(value_trimmed)?;
        }
        "TXT" => {
            validate_txt_value(value_trimmed)?;
        }
        "SRV" => {
            validate_srv_value(value_trimmed)?;
        }
        "CAA" => {
            validate_caa_value(value_trimmed)?;
        }
        "SOA" => {
            // SOA format: "primary-ns responsible-email serial refresh retry expire minimum"
            let parts: Vec<&str> = value_trimmed.split_whitespace().collect();
            if parts.len() < 7 {
                return Err(ValidationError::new("value", "SOA must have 7 fields"));
            }
            validate_fqdn(parts[0])?;
            if !parts[1].contains('.') {
                return Err(ValidationError::new("value", "SOA email must be in FQDN format"));
            }
        }
        _ => {
            return Err(ValidationError::new("record_type", format!("Unsupported record type: {}", rtype_upper)));
        }
    }

    Ok(())
}

/// Validate record type
pub fn validate_record_type(record_type: &str) -> Result<(), ValidationError> {
    let rtype = record_type.trim().to_uppercase();
    let valid_types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SRV", "SOA", "CAA", "DS", "DNSKEY"];
    
    if !valid_types.contains(&rtype.as_str()) {
        return Err(ValidationError::new("record_type", format!("Unsupported record type: {}", rtype)));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_zone_domain() {
        assert!(validate_zone_domain("example.com.").is_ok());
        assert!(validate_zone_domain("sub.example.com.").is_ok());
        assert!(validate_zone_domain("example.com").is_err()); // missing trailing dot
        assert!(validate_zone_domain("example..com.").is_err()); // empty label
        assert!(validate_zone_domain("").is_err());
    }

    #[test]
    fn test_validate_ipv4() {
        assert!(validate_ipv4("192.168.1.1").is_ok());
        assert!(validate_ipv4("192.168.1.256").is_err());
        assert!(validate_ipv4("not-an-ip").is_err());
    }

    #[test]
    fn test_validate_ipv6() {
        assert!(validate_ipv6("::1").is_ok());
        assert!(validate_ipv6("2001:db8::1").is_ok());
        assert!(validate_ipv6("not-an-ipv6").is_err());
    }

    #[test]
    fn test_validate_fqdn() {
        assert!(validate_fqdn("example.com.").is_ok());
        assert!(validate_fqdn("example.com").is_err()); // missing dot
        assert!(validate_fqdn("").is_err());
    }

    #[test]
    fn test_validate_ttl() {
        assert!(validate_ttl(3600).is_ok());
        assert!(validate_ttl(0).is_err());
        assert!(validate_ttl(2147483647).is_ok());
        assert!(validate_ttl(2147483648).is_err());
    }
}
