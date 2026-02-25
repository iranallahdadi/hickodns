/// DNS Manager - Handles automatic zone file generation and DNS server reload
/// This is the core of the Option B architecture: control-api manages the database
/// and generates zone files, the DNS server watches those files and reloads automatically
use std::path::Path;
use log::{error, info, warn};
use std::sync::Arc;
use tokio_postgres::Client;
use crate::zone_file_generator;

pub struct DnsManager {
    config_dir: String,
}

impl DnsManager {
    pub fn new(config_dir: String) -> Self {
        Self { config_dir }
    }

    /// Regenerate all zone files - called after any zone or record mutation
    pub async fn regenerate_zones(&self, db: Arc<Client>) -> Result<(), DnsManagerError> {
        self.ensure_config_dir_exists()?;
        zone_file_generator::generate_all(&self.config_dir, db).await
            .map_err(|e| DnsManagerError::GenerationFailed(e.to_string()))
    }

    fn ensure_config_dir_exists(&self) -> Result<(), DnsManagerError> {
        std::fs::create_dir_all(&self.config_dir)
            .map_err(|e| DnsManagerError::DirectoryError(e.to_string()))?;
        Ok(())
    }

    /// Get the path to the zone directory
    pub fn zone_dir(&self) -> &String {
        &self.config_dir
    }

    /// Get the path to the named.toml config file
    pub fn named_config_path(&self) -> String {
        format!("{}/named.toml", self.config_dir)
    }

    /// Check if zone files have been generated
    pub fn is_configured(&self) -> bool {
        Path::new(&self.named_config_path()).exists()
    }
}

#[derive(Debug)]
pub enum DnsManagerError {
    GenerationFailed(String),
    DirectoryError(String),
}

impl std::fmt::Display for DnsManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsManagerError::GenerationFailed(msg) => write!(f, "Zone generation failed: {}", msg),
            DnsManagerError::DirectoryError(msg) => write!(f, "Directory error: {}", msg),
        }
    }
}

impl std::error::Error for DnsManagerError {}
