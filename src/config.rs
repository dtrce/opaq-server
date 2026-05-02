use zeroize::Zeroizing;

pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub db_path: String,
    pub master_passphrase: Option<Zeroizing<String>>,
    pub master_key_error: Option<String>,
}

impl ServerConfig {
    pub fn from_env<F>(get: F) -> Self
    where
        F: Fn(&str) -> Option<String>,
    {
        let (master_passphrase, master_key_error) = match get("OPAQ_MASTER_KEY") {
            Some(raw) => match validate_master_passphrase(&raw) {
                Ok(p) => (Some(p), None),
                Err(err) => (None, Some(err)),
            },
            None => (None, None),
        };
        Self {
            host: get("OPAQ_HOST").unwrap_or_else(|| "127.0.0.1".into()),
            port: get("OPAQ_PORT")
                .and_then(|p| p.parse().ok())
                .unwrap_or(6727),
            db_path: get("OPAQ_DB").unwrap_or_else(|| "opaq.db".into()),
            master_passphrase,
            master_key_error,
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self::from_env(|k| std::env::var(k).ok())
    }
}

pub fn validate_master_passphrase(s: &str) -> Result<Zeroizing<String>, String> {
    let trimmed = s.trim();
    if trimmed.len() < 32 {
        return Err("OPAQ_MASTER_KEY must be at least 32 characters".to_string());
    }
    if !trimmed.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err("OPAQ_MASTER_KEY must contain only ASCII letters and digits".to_string());
    }
    Ok(Zeroizing::new(trimmed.to_string()))
}

#[cfg(test)]
mod tests {
    use super::ServerConfig;

    #[test]
    fn defaults_to_port_6727_when_env_port_is_unset() {
        let config = ServerConfig::from_env(|_| None);
        assert_eq!(config.port, 6727);
    }

    #[test]
    fn parses_port_from_env_getter() {
        let config = ServerConfig::from_env(|k| match k {
            "OPAQ_PORT" => Some("4242".into()),
            _ => None,
        });
        assert_eq!(config.port, 4242);
    }

    #[test]
    fn invalid_port_falls_back_to_default() {
        let config = ServerConfig::from_env(|k| match k {
            "OPAQ_PORT" => Some("not-a-number".into()),
            _ => None,
        });
        assert_eq!(config.port, 6727);
    }

    #[test]
    fn parses_master_passphrase_from_env_getter() {
        let raw = "a".repeat(32);
        let config = ServerConfig::from_env(|k| match k {
            "OPAQ_MASTER_KEY" => Some(raw.clone()),
            _ => None,
        });
        assert_eq!(config.master_passphrase.as_deref().map(|s| s.len()), Some(32));
        assert!(config.master_key_error.is_none());
    }

    #[test]
    fn rejects_master_key_shorter_than_32_chars() {
        let config = ServerConfig::from_env(|k| match k {
            "OPAQ_MASTER_KEY" => Some("a".repeat(31)),
            _ => None,
        });
        assert!(config.master_passphrase.is_none());
        assert_eq!(
            config.master_key_error.as_deref(),
            Some("OPAQ_MASTER_KEY must be at least 32 characters")
        );
    }

    #[test]
    fn rejects_master_key_with_non_alphanumeric_chars() {
        let config = ServerConfig::from_env(|k| match k {
            "OPAQ_MASTER_KEY" => Some(format!("{}!", "a".repeat(31))),
            _ => None,
        });
        assert!(config.master_passphrase.is_none());
        assert_eq!(
            config.master_key_error.as_deref(),
            Some("OPAQ_MASTER_KEY must contain only ASCII letters and digits")
        );
    }
}
