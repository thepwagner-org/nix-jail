use crate::proxy::llm::ToolCall;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

/// Key for tracking request statistics with multiple dimensions
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RequestKey {
    pub host: String,
    pub method: String,
    pub status: u16,
    pub credential: String, // empty string if none
    pub decision: String,   // "approved" or "denied"
}

/// LLM API usage statistics summary
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LlmStatsSummary {
    /// Total input/prompt tokens across all requests
    pub total_input_tokens: u64,
    /// Total output/completion tokens across all requests
    pub total_output_tokens: u64,
    /// Total cache read tokens across all requests (Anthropic only)
    pub total_cache_read_tokens: u64,
    /// Request count by model name, sorted by count descending
    pub requests_by_model: Vec<(String, u64)>,
    /// Tool call count by tool name, sorted by count descending
    pub tool_calls: Vec<(String, u64)>,
}

/// Serializable proxy statistics for file output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyStatsSummary {
    /// Legacy format for backwards compatibility
    pub approved: Vec<(String, u64)>,
    pub denied: Vec<(String, u64)>,
    /// New detailed format with all dimensions
    #[serde(default)]
    pub requests: Vec<(RequestKey, u64)>,
    /// LLM API usage statistics
    #[serde(default)]
    pub llm: Option<LlmStatsSummary>,
}

/// Thread-safe statistics tracking for proxy requests
#[derive(Debug, Default)]
pub struct ProxyStats {
    approved: Mutex<HashMap<String, u64>>,
    denied: Mutex<HashMap<String, u64>>,
    /// Detailed request tracking with all dimensions
    requests: Mutex<HashMap<RequestKey, u64>>,
    /// LLM token usage tracking
    llm_input_tokens: Mutex<u64>,
    llm_output_tokens: Mutex<u64>,
    llm_cache_read_tokens: Mutex<u64>,
    /// LLM request count by model
    llm_requests_by_model: Mutex<HashMap<String, u64>>,
    /// LLM tool call count by tool name
    llm_tool_calls: Mutex<HashMap<String, u64>>,
}

impl ProxyStats {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an approved request for the given hostname.
    /// Increments the counter for this hostname.
    pub fn record_approved(&self, hostname: &str) {
        // Safety: mutex poisoning should panic - indicates another thread panicked
        #[allow(clippy::expect_used)]
        let mut map = self.approved.lock().expect("operation failed");
        *map.entry(hostname.to_string()).or_insert(0) += 1;
    }

    /// Record a denied request for the given hostname.
    /// Returns true if this is the first time this hostname was denied (should log),
    /// false otherwise (already logged, don't spam).
    pub fn record_denied(&self, hostname: &str) -> bool {
        // Safety: mutex poisoning should panic - indicates another thread panicked
        #[allow(clippy::expect_used)]
        let mut map = self.denied.lock().expect("operation failed");
        let entry = map.entry(hostname.to_string()).or_insert(0);
        let is_first = *entry == 0;
        *entry += 1;
        is_first
    }

    /// Record a request with full dimensional tracking
    pub fn record_request(
        &self,
        host: &str,
        method: &str,
        status: u16,
        credential: Option<&str>,
        approved: bool,
    ) {
        let key = RequestKey {
            host: host.to_string(),
            method: method.to_string(),
            status,
            credential: credential.unwrap_or("").to_string(),
            decision: if approved { "approved" } else { "denied" }.to_string(),
        };

        #[allow(clippy::expect_used)]
        let mut map = self.requests.lock().expect("operation failed");
        *map.entry(key).or_insert(0) += 1;
    }

    /// Record LLM API usage metrics from a response
    pub fn record_llm_metrics(
        &self,
        model: Option<&str>,
        input_tokens: Option<u64>,
        output_tokens: Option<u64>,
        cache_read_tokens: Option<u64>,
        tool_calls: &[ToolCall],
    ) {
        // Record token counts
        if let Some(tokens) = input_tokens {
            #[allow(clippy::expect_used)]
            let mut total = self.llm_input_tokens.lock().expect("operation failed");
            *total += tokens;
        }
        if let Some(tokens) = output_tokens {
            #[allow(clippy::expect_used)]
            let mut total = self.llm_output_tokens.lock().expect("operation failed");
            *total += tokens;
        }
        if let Some(tokens) = cache_read_tokens {
            #[allow(clippy::expect_used)]
            let mut total = self.llm_cache_read_tokens.lock().expect("operation failed");
            *total += tokens;
        }

        // Record model usage
        let model_name = model.unwrap_or("unknown").to_string();
        {
            #[allow(clippy::expect_used)]
            let mut map = self.llm_requests_by_model.lock().expect("operation failed");
            *map.entry(model_name).or_insert(0) += 1;
        }

        // Record tool calls (by name only for aggregate stats)
        {
            #[allow(clippy::expect_used)]
            let mut map = self.llm_tool_calls.lock().expect("operation failed");
            for tool in tool_calls {
                *map.entry(tool.name.clone()).or_insert(0) += 1;
            }
        }
    }

    /// Get summary statistics as a serializable struct
    pub fn summary(&self) -> ProxyStatsSummary {
        #[allow(clippy::expect_used)]
        let approved = self.approved.lock().expect("operation failed");
        #[allow(clippy::expect_used)]
        let denied = self.denied.lock().expect("operation failed");
        #[allow(clippy::expect_used)]
        let requests = self.requests.lock().expect("operation failed");

        let mut approved_vec: Vec<_> = approved.iter().map(|(k, v)| (k.clone(), *v)).collect();
        approved_vec.sort_by(|a, b| b.1.cmp(&a.1));

        let mut denied_vec: Vec<_> = denied.iter().map(|(k, v)| (k.clone(), *v)).collect();
        denied_vec.sort_by(|a, b| b.1.cmp(&a.1));

        let mut requests_vec: Vec<_> = requests.iter().map(|(k, v)| (k.clone(), *v)).collect();
        requests_vec.sort_by(|a, b| b.1.cmp(&a.1));

        // Build LLM stats summary
        #[allow(clippy::expect_used)]
        let input_tokens = *self.llm_input_tokens.lock().expect("operation failed");
        #[allow(clippy::expect_used)]
        let output_tokens = *self.llm_output_tokens.lock().expect("operation failed");
        #[allow(clippy::expect_used)]
        let cache_read_tokens = *self.llm_cache_read_tokens.lock().expect("operation failed");
        #[allow(clippy::expect_used)]
        let models = self.llm_requests_by_model.lock().expect("operation failed");
        #[allow(clippy::expect_used)]
        let tools = self.llm_tool_calls.lock().expect("operation failed");

        let llm = if input_tokens > 0
            || output_tokens > 0
            || cache_read_tokens > 0
            || !models.is_empty()
            || !tools.is_empty()
        {
            let mut models_vec: Vec<_> = models.iter().map(|(k, v)| (k.clone(), *v)).collect();
            models_vec.sort_by(|a, b| b.1.cmp(&a.1));

            let mut tools_vec: Vec<_> = tools.iter().map(|(k, v)| (k.clone(), *v)).collect();
            tools_vec.sort_by(|a, b| b.1.cmp(&a.1));

            Some(LlmStatsSummary {
                total_input_tokens: input_tokens,
                total_output_tokens: output_tokens,
                total_cache_read_tokens: cache_read_tokens,
                requests_by_model: models_vec,
                tool_calls: tools_vec,
            })
        } else {
            None
        };

        ProxyStatsSummary {
            approved: approved_vec,
            denied: denied_vec,
            requests: requests_vec,
            llm,
        }
    }

    /// Write stats to a JSON file for the orchestrator to read after job completes
    pub fn write_to_file(&self, path: &Path) -> std::io::Result<()> {
        let summary = self.summary();
        let json = serde_json::to_string(&summary)?;
        std::fs::write(path, json)
    }
}
