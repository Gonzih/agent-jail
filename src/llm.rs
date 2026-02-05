//! LLM Interceptor — integrates mock-llm-service to capture all LLM API calls.
//!
//! On jail creation: creates a mock-llm-service session in record mode.
//! Injects proxy URL + API key into jail environment variables.
//! All agent LLM calls route through the proxy → recorded.
//! On jail stop: session switches to replay mode.
//!
//! Integration with mock-llm-service at configurable URL (default: http://localhost:8081).

use crate::error::ApiError;
use crate::types::JailId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Configuration for the LLM interceptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmInterceptorConfig {
    /// Whether LLM interception is enabled for this jail.
    pub enabled: bool,
    /// Which LLM provider to intercept.
    pub provider: LlmProvider,
}

impl Default for LlmInterceptorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            provider: LlmProvider::Openai,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum LlmProvider {
    Openai,
    Anthropic,
}

/// State of an LLM interceptor session for a jail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmSession {
    pub jail_id: JailId,
    /// mock-llm-service session ID
    pub session_id: String,
    /// API key for the proxy (format: mlm_xxx)
    pub api_key: String,
    /// Current mode
    pub mode: LlmSessionMode,
    /// Provider
    pub provider: LlmProvider,
    /// Number of recorded LLM calls
    pub recordings_count: u64,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum LlmSessionMode {
    Record,
    Replay,
}

/// Client for communicating with mock-llm-service.
pub struct LlmInterceptor {
    pub base_url: String,
    client: reqwest::Client,
}

impl LlmInterceptor {
    pub fn new(base_url: String) -> Self {
        Self {
            base_url,
            client: reqwest::Client::new(),
        }
    }

    /// Create a new recording session in mock-llm-service.
    pub async fn create_session(
        &self,
        jail_id: &str,
        provider: &LlmProvider,
    ) -> Result<LlmSession, ApiError> {
        let provider_str = match provider {
            LlmProvider::Openai => "openai",
            LlmProvider::Anthropic => "anthropic",
        };

        let body = serde_json::json!({
            "name": format!("jail-{}", jail_id),
            "mode": "record",
            "provider": provider_str,
            "description": format!("Auto-created for jail {}", jail_id),
        });

        let resp = self
            .client
            .post(format!("{}/sessions", self.base_url))
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                ApiError::Internal(format!("Failed to connect to mock-llm-service: {}", e))
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(ApiError::Internal(format!(
                "mock-llm-service returned {}: {}",
                status, text
            )));
        }

        let response: serde_json::Value = resp.json().await.map_err(|e| {
            ApiError::Internal(format!("Failed to parse mock-llm-service response: {}", e))
        })?;

        let data = response
            .get("data")
            .ok_or_else(|| ApiError::Internal("Missing 'data' in response".into()))?;

        let session_id = data["id"]
            .as_str()
            .ok_or_else(|| ApiError::Internal("Missing session id".into()))?
            .to_string();

        let api_key = data["api_key"]
            .as_str()
            .ok_or_else(|| ApiError::Internal("Missing api_key".into()))?
            .to_string();

        Ok(LlmSession {
            jail_id: jail_id.to_string(),
            session_id,
            api_key,
            mode: LlmSessionMode::Record,
            provider: provider.clone(),
            recordings_count: 0,
            created_at: Utc::now(),
        })
    }

    /// Switch session mode (record → replay or vice versa).
    pub async fn switch_mode(
        &self,
        session_id: &str,
        mode: &LlmSessionMode,
    ) -> Result<(), ApiError> {
        let mode_str = match mode {
            LlmSessionMode::Record => "record",
            LlmSessionMode::Replay => "replay",
        };

        let body = serde_json::json!({ "mode": mode_str });

        let resp = self
            .client
            .post(format!("{}/sessions/{}/mode", self.base_url, session_id))
            .json(&body)
            .send()
            .await
            .map_err(|e| ApiError::Internal(format!("Failed to switch mode: {}", e)))?;

        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(ApiError::Internal(format!(
                "Failed to switch session mode: {}",
                text
            )));
        }

        Ok(())
    }

    /// Get session info (recordings count, etc).
    pub async fn get_session(&self, session_id: &str) -> Result<serde_json::Value, ApiError> {
        let resp = self
            .client
            .get(format!("{}/sessions/{}", self.base_url, session_id))
            .send()
            .await
            .map_err(|e| ApiError::Internal(format!("Failed to get session: {}", e)))?;

        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(ApiError::Internal(format!(
                "Failed to get session: {}",
                text
            )));
        }

        let response: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| ApiError::Internal(format!("Failed to parse response: {}", e)))?;

        Ok(response)
    }

    /// List recordings for a session.
    pub async fn list_recordings(&self, session_id: &str) -> Result<serde_json::Value, ApiError> {
        let resp = self
            .client
            .get(format!(
                "{}/sessions/{}/recordings",
                self.base_url, session_id
            ))
            .send()
            .await
            .map_err(|e| ApiError::Internal(format!("Failed to list recordings: {}", e)))?;

        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(ApiError::Internal(format!(
                "Failed to list recordings: {}",
                text
            )));
        }

        resp.json()
            .await
            .map_err(|e| ApiError::Internal(format!("Failed to parse recordings: {}", e)))
    }

    /// Delete a session and all its recordings.
    pub async fn delete_session(&self, session_id: &str) -> Result<(), ApiError> {
        let resp = self
            .client
            .delete(format!("{}/sessions/{}", self.base_url, session_id))
            .send()
            .await
            .map_err(|e| ApiError::Internal(format!("Failed to delete session: {}", e)))?;

        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(ApiError::Internal(format!(
                "Failed to delete session: {}",
                text
            )));
        }

        Ok(())
    }

    /// Environment variables to inject into the jail for LLM interception.
    pub fn env_vars(&self, session: &LlmSession) -> Vec<(String, String)> {
        let mut vars = vec![
            ("MOCK_LLM_PROXY_URL".to_string(), self.base_url.clone()),
            ("MOCK_LLM_API_KEY".to_string(), session.api_key.clone()),
            (
                "MOCK_LLM_SESSION_ID".to_string(),
                session.session_id.clone(),
            ),
        ];

        // Override standard LLM SDK environment variables to route through proxy
        match session.provider {
            LlmProvider::Openai => {
                vars.push(("OPENAI_API_KEY".to_string(), session.api_key.clone()));
                vars.push((
                    "OPENAI_BASE_URL".to_string(),
                    format!("{}/v1", self.base_url),
                ));
            }
            LlmProvider::Anthropic => {
                vars.push(("ANTHROPIC_API_KEY".to_string(), session.api_key.clone()));
                vars.push(("ANTHROPIC_BASE_URL".to_string(), self.base_url.clone()));
            }
        }

        vars
    }

    /// Check if mock-llm-service is reachable.
    pub async fn health_check(&self) -> bool {
        self.client
            .get(format!("{}/health", self.base_url))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_llm_interceptor_config_default() {
        let config = LlmInterceptorConfig::default();
        assert!(config.enabled);
        assert_eq!(config.provider, LlmProvider::Openai);
    }

    #[test]
    fn test_llm_session_serialization() {
        let session = LlmSession {
            jail_id: "jail_test123456".into(),
            session_id: "uuid-here".into(),
            api_key: "mlm_abc123".into(),
            mode: LlmSessionMode::Record,
            provider: LlmProvider::Openai,
            recordings_count: 0,
            created_at: Utc::now(),
        };
        let json = serde_json::to_string(&session).unwrap();
        let parsed: LlmSession = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.jail_id, "jail_test123456");
        assert_eq!(parsed.api_key, "mlm_abc123");
        assert_eq!(parsed.mode, LlmSessionMode::Record);
    }

    #[test]
    fn test_env_vars_openai() {
        let interceptor = LlmInterceptor::new("http://localhost:8081".into());
        let session = LlmSession {
            jail_id: "jail_test".into(),
            session_id: "sess-123".into(),
            api_key: "mlm_key123".into(),
            mode: LlmSessionMode::Record,
            provider: LlmProvider::Openai,
            recordings_count: 0,
            created_at: Utc::now(),
        };

        let vars = interceptor.env_vars(&session);
        let map: std::collections::HashMap<_, _> = vars.into_iter().collect();

        assert_eq!(map["MOCK_LLM_PROXY_URL"], "http://localhost:8081");
        assert_eq!(map["MOCK_LLM_API_KEY"], "mlm_key123");
        assert_eq!(map["OPENAI_API_KEY"], "mlm_key123");
        assert_eq!(map["OPENAI_BASE_URL"], "http://localhost:8081/v1");
    }

    #[test]
    fn test_env_vars_anthropic() {
        let interceptor = LlmInterceptor::new("http://localhost:8081".into());
        let session = LlmSession {
            jail_id: "jail_test".into(),
            session_id: "sess-123".into(),
            api_key: "mlm_key456".into(),
            mode: LlmSessionMode::Record,
            provider: LlmProvider::Anthropic,
            recordings_count: 0,
            created_at: Utc::now(),
        };

        let vars = interceptor.env_vars(&session);
        let map: std::collections::HashMap<_, _> = vars.into_iter().collect();

        assert_eq!(map["ANTHROPIC_API_KEY"], "mlm_key456");
        assert_eq!(map["ANTHROPIC_BASE_URL"], "http://localhost:8081");
    }

    #[test]
    fn test_provider_serde() {
        let providers = vec![LlmProvider::Openai, LlmProvider::Anthropic];
        for p in providers {
            let json = serde_json::to_string(&p).unwrap();
            let parsed: LlmProvider = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, p);
        }
    }

    #[test]
    fn test_session_mode_serde() {
        let modes = vec![LlmSessionMode::Record, LlmSessionMode::Replay];
        for m in modes {
            let json = serde_json::to_string(&m).unwrap();
            let parsed: LlmSessionMode = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, m);
        }
    }
}
