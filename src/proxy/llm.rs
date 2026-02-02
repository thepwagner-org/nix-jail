//! LLM API response parsing for metrics extraction
//!
//! Parses SSE streaming and non-streaming responses from Anthropic and OpenAI APIs
//! to extract token usage, model information, and tool call metrics.

use crate::config::LlmProvider;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Maximum length for tool argument values (truncated with "..." suffix)
const MAX_ARG_VALUE_LEN: usize = 256;

/// A tool call with its name and arguments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    /// Tool name (e.g., "Read", "Edit", "Bash")
    pub name: String,
    /// Tool arguments as JSON (with large values truncated)
    pub arguments: serde_json::Value,
}

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
    /// Tool calls with names and truncated arguments
    pub tool_calls: Vec<ToolCall>,
}

/// In-progress tool call being accumulated from streaming events
#[derive(Debug, Default)]
struct PendingToolCall {
    name: String,
    /// Accumulated partial JSON for the arguments
    input_json: String,
}

/// Truncate a string to max_len bytes, adding "..." if truncated
fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        // Find a valid UTF-8 boundary
        let mut end = max_len.saturating_sub(3); // Leave room for "..."
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}...", &s[..end])
    }
}

/// Recursively truncate string values in a JSON value
fn truncate_json_values(value: &mut serde_json::Value, max_len: usize) {
    match value {
        serde_json::Value::String(s) => {
            if s.len() > max_len {
                *s = truncate_string(s, max_len);
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                truncate_json_values(item, max_len);
            }
        }
        serde_json::Value::Object(map) => {
            for (_, v) in map.iter_mut() {
                truncate_json_values(v, max_len);
            }
        }
        _ => {} // Numbers, bools, null don't need truncation
    }
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
    /// In-progress tool calls indexed by content block index
    pending_tools: HashMap<u64, PendingToolCall>,
}

impl StreamingMetricsAccumulator {
    /// Create a new accumulator for the given provider
    pub fn new(provider: LlmProvider) -> Self {
        Self {
            provider: Some(provider),
            metrics: LlmMetrics::default(),
            line_buffer: String::new(),
            pending_tools: HashMap::new(),
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
    /// - content_block_start: Contains tool_use blocks with tool names and starts accumulation
    /// - content_block_delta: Contains partial JSON for tool arguments
    /// - content_block_stop: Finalizes tool call with complete arguments
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
                // Start tracking a new tool_use content block
                if let (Some(index), Some(content_block)) = (
                    json.get("index").and_then(|v| v.as_u64()),
                    json.get("content_block"),
                ) {
                    if content_block.get("type").and_then(|v| v.as_str()) == Some("tool_use") {
                        if let Some(name) = content_block.get("name").and_then(|v| v.as_str()) {
                            let _ = self.pending_tools.insert(
                                index,
                                PendingToolCall {
                                    name: name.to_string(),
                                    input_json: String::new(),
                                },
                            );
                        }
                    }
                }
            }
            Some("content_block_delta") => {
                // Accumulate partial JSON for tool arguments
                if let (Some(index), Some(delta)) = (
                    json.get("index").and_then(|v| v.as_u64()),
                    json.get("delta"),
                ) {
                    if delta.get("type").and_then(|v| v.as_str()) == Some("input_json_delta") {
                        if let Some(partial) = delta.get("partial_json").and_then(|v| v.as_str()) {
                            if let Some(pending) = self.pending_tools.get_mut(&index) {
                                pending.input_json.push_str(partial);
                            }
                        }
                    }
                }
            }
            Some("content_block_stop") => {
                // Finalize tool call with complete arguments
                if let Some(index) = json.get("index").and_then(|v| v.as_u64()) {
                    if let Some(pending) = self.pending_tools.remove(&index) {
                        // Parse and truncate arguments
                        let arguments = if pending.input_json.is_empty() {
                            serde_json::Value::Object(serde_json::Map::new())
                        } else {
                            match serde_json::from_str::<serde_json::Value>(&pending.input_json) {
                                Ok(mut val) => {
                                    truncate_json_values(&mut val, MAX_ARG_VALUE_LEN);
                                    val
                                }
                                Err(_) => {
                                    // If parsing fails, store as raw string (truncated)
                                    let truncated =
                                        truncate_string(&pending.input_json, MAX_ARG_VALUE_LEN);
                                    serde_json::Value::String(truncated)
                                }
                            }
                        };

                        self.metrics.tool_calls.push(ToolCall {
                            name: pending.name,
                            arguments,
                        });
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
    /// OpenAI sends incremental deltas, with usage in final chunk.
    /// Tool calls are accumulated across multiple delta chunks.
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
                            let index =
                                tool_call.get("index").and_then(|v| v.as_u64()).unwrap_or(0);

                            if let Some(function) = tool_call.get("function") {
                                // If name is present, start a new tool call
                                if let Some(name) = function.get("name").and_then(|v| v.as_str()) {
                                    let _ = self.pending_tools.insert(
                                        index,
                                        PendingToolCall {
                                            name: name.to_string(),
                                            input_json: String::new(),
                                        },
                                    );
                                }

                                // Accumulate arguments
                                if let Some(args) =
                                    function.get("arguments").and_then(|v| v.as_str())
                                {
                                    if let Some(pending) = self.pending_tools.get_mut(&index) {
                                        pending.input_json.push_str(args);
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

    /// Check if we have complete metrics (model + input + output tokens)
    ///
    /// For Anthropic, this is true after receiving message_delta with output_tokens.
    /// For OpenAI, this is true after receiving a chunk with usage data.
    pub fn is_complete(&self) -> bool {
        self.metrics.model.is_some()
            && self.metrics.input_tokens.is_some()
            && self.metrics.output_tokens.is_some()
    }

    /// Get a reference to current metrics (for early recording)
    pub fn metrics(&self) -> &LlmMetrics {
        &self.metrics
    }

    /// Finalize and return accumulated metrics
    ///
    /// For OpenAI, this also finalizes any pending tool calls that were
    /// accumulated across delta chunks.
    pub fn finalize(mut self) -> LlmMetrics {
        // Finalize any remaining pending tool calls (OpenAI doesn't have content_block_stop)
        for (_, pending) in self.pending_tools.drain() {
            let arguments = if pending.input_json.is_empty() {
                serde_json::Value::Object(serde_json::Map::new())
            } else {
                match serde_json::from_str::<serde_json::Value>(&pending.input_json) {
                    Ok(mut val) => {
                        truncate_json_values(&mut val, MAX_ARG_VALUE_LEN);
                        val
                    }
                    Err(_) => {
                        // If parsing fails, store as raw string (truncated)
                        let truncated = truncate_string(&pending.input_json, MAX_ARG_VALUE_LEN);
                        serde_json::Value::String(truncated)
                    }
                }
            };

            self.metrics.tool_calls.push(ToolCall {
                name: pending.name,
                arguments,
            });
        }

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
                            // Get arguments and truncate values
                            let arguments = if let Some(input) = block.get("input") {
                                let mut args = input.clone();
                                truncate_json_values(&mut args, MAX_ARG_VALUE_LEN);
                                args
                            } else {
                                serde_json::Value::Object(serde_json::Map::new())
                            };
                            metrics.tool_calls.push(ToolCall {
                                name: name.to_string(),
                                arguments,
                            });
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
                                        // Get arguments and truncate values
                                        let arguments = if let Some(args_str) =
                                            function.get("arguments").and_then(|v| v.as_str())
                                        {
                                            match serde_json::from_str::<serde_json::Value>(
                                                args_str,
                                            ) {
                                                Ok(mut args) => {
                                                    truncate_json_values(
                                                        &mut args,
                                                        MAX_ARG_VALUE_LEN,
                                                    );
                                                    args
                                                }
                                                Err(_) => {
                                                    // Store raw string if not valid JSON
                                                    serde_json::Value::String(truncate_string(
                                                        args_str,
                                                        MAX_ARG_VALUE_LEN,
                                                    ))
                                                }
                                            }
                                        } else {
                                            serde_json::Value::Object(serde_json::Map::new())
                                        };
                                        metrics.tool_calls.push(ToolCall {
                                            name: name.to_string(),
                                            arguments,
                                        });
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
        assert_eq!(metrics.tool_calls.len(), 1);
        assert_eq!(metrics.tool_calls[0].name, "Bash");
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
        assert_eq!(metrics.tool_calls.len(), 1);
        assert_eq!(metrics.tool_calls[0].name, "get_weather");
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

        // Tool use requires content_block_start with index, then content_block_stop to finalize
        let start_chunk = b"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"name\":\"Read\"}}\n\n";
        acc.process_chunk(start_chunk);

        // Finalize the tool call with content_block_stop
        let stop_chunk =
            b"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n";
        acc.process_chunk(stop_chunk);

        let metrics = acc.finalize();
        assert_eq!(metrics.tool_calls.len(), 1);
        assert_eq!(metrics.tool_calls[0].name, "Read");
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
