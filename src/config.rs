use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub data_dir: PathBuf,
    /// URL of mock-llm-service for LLM interception
    pub mock_llm_url: String,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            host: std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".into()),
            port: std::env::var("PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(8082),
            data_dir: std::env::var("DATA_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("./data")),
            mock_llm_url: std::env::var("MOCK_LLM_URL")
                .unwrap_or_else(|_| "http://localhost:8081".into()),
        }
    }

    pub fn jails_dir(&self) -> PathBuf {
        self.data_dir.join("jails")
    }

    pub fn jail_dir(&self, jail_id: &str) -> PathBuf {
        self.jails_dir().join(jail_id)
    }

    pub fn jail_events_dir(&self, jail_id: &str) -> PathBuf {
        self.jail_dir(jail_id).join("events")
    }

    pub fn jail_snapshots_dir(&self, jail_id: &str) -> PathBuf {
        self.jail_dir(jail_id).join("snapshots")
    }

    pub fn jail_rootfs_dir(&self, jail_id: &str) -> PathBuf {
        self.jail_dir(jail_id).join("rootfs")
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".into(),
            port: 8082,
            data_dir: PathBuf::from("./data"),
            mock_llm_url: "http://localhost:8081".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.host, "0.0.0.0");
        assert_eq!(config.port, 8082);
        assert_eq!(config.data_dir, PathBuf::from("./data"));
    }

    #[test]
    fn test_path_helpers() {
        let config = Config {
            data_dir: PathBuf::from("/mnt/storage"),
            ..Config::default()
        };
        assert_eq!(config.jails_dir(), PathBuf::from("/mnt/storage/jails"));
        assert_eq!(
            config.jail_dir("jail_abc123"),
            PathBuf::from("/mnt/storage/jails/jail_abc123")
        );
        assert_eq!(
            config.jail_events_dir("jail_abc123"),
            PathBuf::from("/mnt/storage/jails/jail_abc123/events")
        );
        assert_eq!(
            config.jail_snapshots_dir("jail_abc123"),
            PathBuf::from("/mnt/storage/jails/jail_abc123/snapshots")
        );
        assert_eq!(
            config.jail_rootfs_dir("jail_abc123"),
            PathBuf::from("/mnt/storage/jails/jail_abc123/rootfs")
        );
    }
}
