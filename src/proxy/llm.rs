//! LLM API response parsing for metrics extraction
//!
//! Parses SSE streaming and non-streaming responses from Anthropic and OpenAI APIs
//! to extract token usage, model information, and tool call metrics.

use crate::config::LlmProvider;

/// Extracted metrics from an LLM API response
#[derive(Debug, Default, Clone)]
pub struct LlmMetrics {
    /// Model name (e.g., "claude-sonnet-4-20250514", "gpt-4")
    pub model: Option<String>,
    /// Input/prompt token count
    pub input_tokens: Option<u64>,
    /// Output/completion token count
    pub output_tokens: Option<u64>,
    /// Cache read tokens (Anthropic only)
    pub cache_read_tokens: Option<u64>,
    /// Tool names invoked in this response
    pub tool_calls: Vec<String>,
}

/// Accumulator for parsing SSE streaming responses
///
/// Processes SSE events incrementally as they arrive, accumulating metrics
/// until the stream completes.
#[derive(Debug, Default)]
pub struct StreamingMetricsAccumulator {
    provider: Option<LlmProvider>,
    metrics: LlmMetrics,
    /// Buffer for incomplete SSE lines spanning chunk boundaries
    line_buffer: String,
}

impl StreamingMetricsAccumulator {
    /// Create a new accumulator for the given provider
    pub fn new(provider: LlmProvider) -> Self {
        Self {
            provider: Some(provider),
            metrics: LlmMetrics::default(),
            line_buffer: String::new(),
        }
    }

    /// Process a chunk of SSE data, extracting metrics from complete events
    ///
    /// Handles SSE format:
    /// ```text
    /// event: message_start
    /// data: {"type":"message_start",...}
    ///
    /// event: content_block_start
    /// data: {"type":"content_block_start",...}
    /// ```
    pub fn process_chunk(&mut self, chunk: &[u8]) {
        let chunk_str = match std::str::from_utf8(chunk) {
            Ok(s) => s,
            Err(_) => return, // Skip non-UTF8 chunks
        };

        // Append to buffer and process complete lines
        self.line_buffer.push_str(chunk_str);

        // Process complete lines
        while let Some(newline_pos) = self.line_buffer.find('\n') {
            // Extract line before modifying buffer
            let line = self.line_buffer[..newline_pos]
                .trim_end_matches('\r')
                .to_string();
            self.line_buffer = self.line_buffer[newline_pos + 1..].to_string();

            self.process_line(&line);
        }
    }

    /// Process a single SSE line
    fn process_line(&mut self, line: &str) {
        // Skip empty lines and event type lines
        if line.is_empty() || line.starts_with("event:") {
            return;
        }

        // Parse data lines
        if let Some(data) = line.strip_prefix("data: ") {
            // Skip [DONE] marker
            if data == "[DONE]" {
                return;
            }

            // Parse JSON
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(data) {
                match self.provider {
                    Some(LlmProvider::Anthropic) => self.process_anthropic_event(&json),
                    Some(LlmProvider::OpenAI) => self.process_openai_event(&json),
                    None => {}
                }
            }
        }
    }

    /// Process Anthropic SSE event
    ///
    /// Event types:
    /// - message_start: Contains model name and initial input_tokens
    /// - content_block_start: Contains tool_use blocks with tool names
    /// - message_delta: Contains final output_tokens
    fn process_anthropic_event(&mut self, json: &serde_json::Value) {
        let event_type = json.get("type").and_then(|v| v.as_str());

        match event_type {
            Some("message_start") => {
                // Extract model and initial usage from message_start
                if let Some(message) = json.get("message") {
                    if let Some(model) = message.get("model").and_then(|v| v.as_str()) {
                        self.metrics.model = Some(model.to_string());
                    }
                    if let Some(usage) = message.get("usage") {
                        if let Some(input) = usage.get("input_tokens").and_then(|v| v.as_u64()) {
                            self.metrics.input_tokens = Some(input);
                        }
                        if let Some(cache) = usage
                            .get("cache_read_input_tokens")
                            .and_then(|v| v.as_u64())
                        {
                            self.metrics.cache_read_tokens = Some(cache);
                        }
                    }
                }
            }
            Some("content_block_start") => {
                // Extract tool names from content_block_start
                if let Some(content_block) = json.get("content_block") {
                    if content_block.get("type").and_then(|v| v.as_str()) == Some("tool_use") {
                        if let Some(name) = content_block.get("name").and_then(|v| v.as_str()) {
                            self.metrics.tool_calls.push(name.to_string());
                        }
                    }
                }
            }
            Some("message_delta") => {
                // Extract final output tokens from message_delta
                if let Some(usage) = json.get("usage") {
                    if let Some(output) = usage.get("output_tokens").and_then(|v| v.as_u64()) {
                        self.metrics.output_tokens = Some(output);
                    }
                }
            }
            _ => {}
        }
    }

    /// Process OpenAI SSE event
    ///
    /// OpenAI sends incremental deltas, with usage in final chunk
    fn process_openai_event(&mut self, json: &serde_json::Value) {
        // Extract model (usually in first chunk)
        if self.metrics.model.is_none() {
            if let Some(model) = json.get("model").and_then(|v| v.as_str()) {
                self.metrics.model = Some(model.to_string());
            }
        }

        // Extract tool calls from choices[].delta.tool_calls
        if let Some(choices) = json.get("choices").and_then(|v| v.as_array()) {
            for choice in choices {
                if let Some(delta) = choice.get("delta") {
                    if let Some(tool_calls) = delta.get("tool_calls").and_then(|v| v.as_array()) {
                        for tool_call in tool_calls {
                            if let Some(function) = tool_call.get("function") {
                                if let Some(name) = function.get("name").and_then(|v| v.as_str()) {
                                    // Only add if not already present (OpenAI sends name once)
                                    if !self.metrics.tool_calls.contains(&name.to_string()) {
                                        self.metrics.tool_calls.push(name.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Extract usage from final chunk
        if let Some(usage) = json.get("usage") {
            if let Some(prompt) = usage.get("prompt_tokens").and_then(|v| v.as_u64()) {
                self.metrics.input_tokens = Some(prompt);
            }
            if let Some(completion) = usage.get("completion_tokens").and_then(|v| v.as_u64()) {
                self.metrics.output_tokens = Some(completion);
            }
        }
    }

    /// Finalize and return accumulated metrics
    pub fn finalize(self) -> LlmMetrics {
        self.metrics
    }
}

/// Parse a complete (non-streaming) LLM API response
pub fn parse_llm_response(body: &[u8], provider: LlmProvider) -> Option<LlmMetrics> {
    let json: serde_json::Value = serde_json::from_slice(body).ok()?;

    let mut metrics = LlmMetrics::default();

    match provider {
        LlmProvider::Anthropic => {
            // Model
            if let Some(model) = json.get("model").and_then(|v| v.as_str()) {
                metrics.model = Some(model.to_string());
            }

            // Usage
            if let Some(usage) = json.get("usage") {
                metrics.input_tokens = usage.get("input_tokens").and_then(|v| v.as_u64());
                metrics.output_tokens = usage.get("output_tokens").and_then(|v| v.as_u64());
                metrics.cache_read_tokens = usage
                    .get("cache_read_input_tokens")
                    .and_then(|v| v.as_u64());
            }

            // Tool calls from content array
            if let Some(content) = json.get("content").and_then(|v| v.as_array()) {
                for block in content {
                    if block.get("type").and_then(|v| v.as_str()) == Some("tool_use") {
                        if let Some(name) = block.get("name").and_then(|v| v.as_str()) {
                            metrics.tool_calls.push(name.to_string());
                        }
                    }
                }
            }
        }
        LlmProvider::OpenAI => {
            // Model
            if let Some(model) = json.get("model").and_then(|v| v.as_str()) {
                metrics.model = Some(model.to_string());
            }

            // Usage
            if let Some(usage) = json.get("usage") {
                metrics.input_tokens = usage.get("prompt_tokens").and_then(|v| v.as_u64());
                metrics.output_tokens = usage.get("completion_tokens").and_then(|v| v.as_u64());
            }

            // Tool calls from choices[].message.tool_calls
            if let Some(choices) = json.get("choices").and_then(|v| v.as_array()) {
                for choice in choices {
                    if let Some(message) = choice.get("message") {
                        if let Some(tool_calls) =
                            message.get("tool_calls").and_then(|v| v.as_array())
                        {
                            for tool_call in tool_calls {
                                if let Some(function) = tool_call.get("function") {
                                    if let Some(name) =
                                        function.get("name").and_then(|v| v.as_str())
                                    {
                                        metrics.tool_calls.push(name.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Some(metrics)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_anthropic_response() {
        let body = br#"{
            "model": "claude-sonnet-4-20250514",
            "usage": {
                "input_tokens": 2095,
                "output_tokens": 503,
                "cache_read_input_tokens": 1024
            },
            "content": [
                {"type": "text", "text": "Hello"},
                {"type": "tool_use", "name": "Bash", "input": {}}
            ]
        }"#;

        let metrics = parse_llm_response(body, LlmProvider::Anthropic).unwrap();
        assert_eq!(metrics.model, Some("claude-sonnet-4-20250514".to_string()));
        assert_eq!(metrics.input_tokens, Some(2095));
        assert_eq!(metrics.output_tokens, Some(503));
        assert_eq!(metrics.cache_read_tokens, Some(1024));
        assert_eq!(metrics.tool_calls, vec!["Bash"]);
    }

    #[test]
    fn test_parse_openai_response() {
        let body = br#"{
            "model": "gpt-4",
            "usage": {
                "prompt_tokens": 100,
                "completion_tokens": 50
            },
            "choices": [{
                "message": {
                    "tool_calls": [
                        {"function": {"name": "get_weather"}}
                    ]
                }
            }]
        }"#;

        let metrics = parse_llm_response(body, LlmProvider::OpenAI).unwrap();
        assert_eq!(metrics.model, Some("gpt-4".to_string()));
        assert_eq!(metrics.input_tokens, Some(100));
        assert_eq!(metrics.output_tokens, Some(50));
        assert_eq!(metrics.tool_calls, vec!["get_weather"]);
    }

    #[test]
    fn test_streaming_anthropic_message_start() {
        let mut acc = StreamingMetricsAccumulator::new(LlmProvider::Anthropic);

        let chunk = b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-sonnet-4-20250514\",\"usage\":{\"input_tokens\":100}}}\n\n";
        acc.process_chunk(chunk);

        let metrics = acc.finalize();
        assert_eq!(metrics.model, Some("claude-sonnet-4-20250514".to_string()));
        assert_eq!(metrics.input_tokens, Some(100));
    }

    #[test]
    fn test_streaming_anthropic_tool_use() {
        let mut acc = StreamingMetricsAccumulator::new(LlmProvider::Anthropic);

        let chunk = b"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"content_block\":{\"type\":\"tool_use\",\"name\":\"Read\"}}\n\n";
        acc.process_chunk(chunk);

        let metrics = acc.finalize();
        assert_eq!(metrics.tool_calls, vec!["Read"]);
    }

    #[test]
    fn test_streaming_anthropic_message_delta() {
        let mut acc = StreamingMetricsAccumulator::new(LlmProvider::Anthropic);

        let chunk =
            b"event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":250}}\n\n";
        acc.process_chunk(chunk);

        let metrics = acc.finalize();
        assert_eq!(metrics.output_tokens, Some(250));
    }

    #[test]
    fn test_streaming_split_chunks() {
        let mut acc = StreamingMetricsAccumulator::new(LlmProvider::Anthropic);

        // Split a line across two chunks
        acc.process_chunk(b"event: message_start\ndata: {\"type\":\"message_st");
        acc.process_chunk(b"art\",\"message\":{\"model\":\"claude-3\"}}\n\n");

        let metrics = acc.finalize();
        assert_eq!(metrics.model, Some("claude-3".to_string()));
    }

    #[test]
    fn test_streaming_openai_usage() {
        let mut acc = StreamingMetricsAccumulator::new(LlmProvider::OpenAI);

        let chunk = b"data: {\"model\":\"gpt-4\",\"usage\":{\"prompt_tokens\":50,\"completion_tokens\":25}}\n\n";
        acc.process_chunk(chunk);

        let metrics = acc.finalize();
        assert_eq!(metrics.model, Some("gpt-4".to_string()));
        assert_eq!(metrics.input_tokens, Some(50));
        assert_eq!(metrics.output_tokens, Some(25));
    }

    #[test]
    fn test_streaming_done_marker() {
        let mut acc = StreamingMetricsAccumulator::new(LlmProvider::OpenAI);

        let chunk = b"data: [DONE]\n\n";
        acc.process_chunk(chunk);

        // Should not panic or produce invalid metrics
        let metrics = acc.finalize();
        assert!(metrics.model.is_none());
    }
}
