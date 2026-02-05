//! LLM cost calculation — maps provider/model to per-token pricing.
//!
//! Prices are in USD per token. Updated periodically as providers change rates.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Per-token cost tuple: (input_cost, output_cost) in USD.
pub fn cost_per_token(provider: &str, model: &str) -> (f64, f64) {
    let model_lower = model.to_lowercase();
    match provider {
        "openai" => match () {
            _ if model_lower.starts_with("gpt-4o-mini") => (0.15e-6, 0.60e-6),
            _ if model_lower.starts_with("gpt-4o") => (2.5e-6, 10.0e-6),
            _ if model_lower.starts_with("gpt-4-turbo") => (10.0e-6, 30.0e-6),
            _ if model_lower.starts_with("gpt-4") => (30.0e-6, 60.0e-6),
            _ if model_lower.starts_with("gpt-3.5") => (0.5e-6, 1.5e-6),
            _ if model_lower.starts_with("o1-mini") => (3.0e-6, 12.0e-6),
            _ if model_lower.starts_with("o1") => (15.0e-6, 60.0e-6),
            _ if model_lower.starts_with("o3-mini") => (1.1e-6, 4.4e-6),
            _ if model_lower.starts_with("o3") => (10.0e-6, 40.0e-6),
            _ => (2.5e-6, 10.0e-6), // default to gpt-4o pricing
        },
        "anthropic" => match () {
            _ if model_lower.contains("opus") => (15.0e-6, 75.0e-6),
            _ if model_lower.contains("sonnet") => (3.0e-6, 15.0e-6),
            _ if model_lower.contains("haiku") => (0.8e-6, 4.0e-6),
            _ => (3.0e-6, 15.0e-6), // default to sonnet pricing
        },
        _ => (1.0e-6, 5.0e-6), // conservative unknown provider fallback
    }
}

/// Compute cost in USD given token counts.
pub fn compute_cost(provider: &str, model: &str, input_tokens: u64, output_tokens: u64) -> f64 {
    let (input_rate, output_rate) = cost_per_token(provider, model);
    (input_tokens as f64 * input_rate) + (output_tokens as f64 * output_rate)
}

/// Accumulates cost across multiple LLM requests for a single jail.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CostAccumulator {
    pub total_llm_cost_usd: f64,
    pub total_input_tokens: u64,
    pub total_output_tokens: u64,
    pub total_requests: u64,
    pub cost_by_model: HashMap<String, f64>,
    pub tokens_by_model: HashMap<String, u64>,
}

impl CostAccumulator {
    pub fn record(
        &mut self,
        model: &str,
        input_tokens: u64,
        output_tokens: u64,
        cost_usd: f64,
    ) {
        self.total_requests += 1;
        self.total_input_tokens += input_tokens;
        self.total_output_tokens += output_tokens;
        self.total_llm_cost_usd += cost_usd;
        *self.cost_by_model.entry(model.to_string()).or_default() += cost_usd;
        *self.tokens_by_model.entry(model.to_string()).or_default() +=
            input_tokens + output_tokens;
    }
}

/// A single LLM usage event — one per proxied API call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmUsageEvent {
    pub ts: u64,
    pub jail_id: String,
    pub session_id: String,
    pub request_id: String,
    pub provider: String,
    pub model: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub total_tokens: u64,
    pub cost_usd: f64,
    pub latency_ms: u64,
    pub cached: bool,
}

/// Summary returned by the /cost endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostSummary {
    pub jail_id: String,
    pub total_cost_usd: f64,
    pub total_requests: u64,
    pub total_input_tokens: u64,
    pub total_output_tokens: u64,
    pub by_model: HashMap<String, ModelCostDetail>,
    pub runtime_secs: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelCostDetail {
    pub requests: u64,
    pub cost_usd: f64,
    pub input_tokens: u64,
    pub output_tokens: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openai_gpt4o_pricing() {
        let (input, output) = cost_per_token("openai", "gpt-4o");
        assert!((input - 2.5e-6).abs() < 1e-12);
        assert!((output - 10.0e-6).abs() < 1e-12);
    }

    #[test]
    fn test_openai_gpt4o_mini_pricing() {
        let (input, output) = cost_per_token("openai", "gpt-4o-mini");
        assert!((input - 0.15e-6).abs() < 1e-12);
        assert!((output - 0.60e-6).abs() < 1e-12);
    }

    #[test]
    fn test_anthropic_sonnet_pricing() {
        let (input, output) = cost_per_token("anthropic", "claude-sonnet-4-5-20250929");
        assert!((input - 3.0e-6).abs() < 1e-12);
        assert!((output - 15.0e-6).abs() < 1e-12);
    }

    #[test]
    fn test_anthropic_opus_pricing() {
        let (input, output) = cost_per_token("anthropic", "claude-opus-4-5-20251101");
        assert!((input - 15.0e-6).abs() < 1e-12);
        assert!((output - 75.0e-6).abs() < 1e-12);
    }

    #[test]
    fn test_anthropic_haiku_pricing() {
        let (input, output) = cost_per_token("anthropic", "claude-haiku-4-5-20251001");
        assert!((input - 0.8e-6).abs() < 1e-12);
        assert!((output - 4.0e-6).abs() < 1e-12);
    }

    #[test]
    fn test_unknown_provider_fallback() {
        let (input, output) = cost_per_token("mistral", "mixtral-8x7b");
        assert!((input - 1.0e-6).abs() < 1e-12);
        assert!((output - 5.0e-6).abs() < 1e-12);
    }

    #[test]
    fn test_compute_cost() {
        // 1000 input tokens + 500 output tokens with gpt-4o
        let cost = compute_cost("openai", "gpt-4o", 1000, 500);
        let expected = 1000.0 * 2.5e-6 + 500.0 * 10.0e-6;
        assert!((cost - expected).abs() < 1e-12);
    }

    #[test]
    fn test_compute_cost_zero_tokens() {
        let cost = compute_cost("openai", "gpt-4o", 0, 0);
        assert!((cost - 0.0).abs() < 1e-12);
    }

    #[test]
    fn test_cost_accumulator_record() {
        let mut acc = CostAccumulator::default();
        acc.record("gpt-4o", 1000, 500, 0.0075);
        acc.record("gpt-4o", 2000, 1000, 0.015);
        acc.record("claude-sonnet-4-5-20250929", 500, 200, 0.0045);

        assert_eq!(acc.total_requests, 3);
        assert_eq!(acc.total_input_tokens, 3500);
        assert_eq!(acc.total_output_tokens, 1700);
        assert!((acc.total_llm_cost_usd - 0.027).abs() < 1e-10);
        assert_eq!(acc.cost_by_model.len(), 2);
        assert_eq!(acc.tokens_by_model.len(), 2);
    }

    #[test]
    fn test_cost_accumulator_empty() {
        let acc = CostAccumulator::default();
        assert_eq!(acc.total_requests, 0);
        assert_eq!(acc.total_input_tokens, 0);
        assert!((acc.total_llm_cost_usd - 0.0).abs() < 1e-12);
    }

    #[test]
    fn test_llm_usage_event_serialization() {
        let event = LlmUsageEvent {
            ts: 1706000000000,
            jail_id: "jail_abc123".into(),
            session_id: "sess-123".into(),
            request_id: "req-456".into(),
            provider: "openai".into(),
            model: "gpt-4o".into(),
            input_tokens: 1000,
            output_tokens: 500,
            total_tokens: 1500,
            cost_usd: 0.0075,
            latency_ms: 1234,
            cached: false,
        };
        let json = serde_json::to_string(&event).unwrap();
        let parsed: LlmUsageEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.jail_id, "jail_abc123");
        assert_eq!(parsed.input_tokens, 1000);
        assert!((parsed.cost_usd - 0.0075).abs() < 1e-12);
    }

    #[test]
    fn test_case_insensitive_model_matching() {
        let (input, _) = cost_per_token("openai", "GPT-4o");
        assert!((input - 2.5e-6).abs() < 1e-12);

        let (input, _) = cost_per_token("anthropic", "Claude-OPUS-4-5");
        assert!((input - 15.0e-6).abs() < 1e-12);
    }
}
