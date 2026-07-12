//! OpenAI Chat Completions provider (SSE streaming).

use async_trait::async_trait;
use futures::StreamExt;
use serde_json::json;
use tokio_stream::wrappers::ReceiverStream;

use super::sse::{sse_data, LineBuffer};
use super::{ChatProvider, ChatRequest, EventStream, ProviderError, StreamEvent};

pub struct OpenAiProvider {
    http: reqwest::Client,
    base_url: String,
    api_key: String,
}

impl OpenAiProvider {
    pub fn new(http: reqwest::Client, base_url: String, api_key: String) -> Self {
        Self {
            http,
            base_url,
            api_key,
        }
    }
}

/// Parse one SSE line from the OpenAI stream. `None` means "ignore this line";
/// `Some(Err)` surfaces a provider-signalled error.
pub(crate) fn parse_line(line: &str) -> Option<Result<StreamEvent, ProviderError>> {
    let data = sse_data(line)?;
    if data == "[DONE]" {
        return Some(Ok(StreamEvent::Done));
    }
    let value: serde_json::Value = serde_json::from_str(data).ok()?;
    // OpenAI reports mid-stream failures as `{"error": {...}}`.
    if let Some(error) = value.get("error") {
        let kind = error
            .get("type")
            .and_then(|t| t.as_str())
            .or_else(|| error.get("code").and_then(|c| c.as_str()))
            .unwrap_or("unknown");
        return Some(Err(ProviderError::Request(format!(
            "openai stream error: {kind}"
        ))));
    }
    let delta = value
        .get("choices")?
        .get(0)?
        .get("delta")?
        .get("content")?
        .as_str()?;
    if delta.is_empty() {
        return None;
    }
    Some(Ok(StreamEvent::Delta(delta.to_string())))
}

#[async_trait]
impl ChatProvider for OpenAiProvider {
    fn name(&self) -> &'static str {
        "openai"
    }

    async fn stream_chat(&self, request: ChatRequest) -> Result<EventStream, ProviderError> {
        let mut body = serde_json::Map::new();
        body.insert("model".into(), json!(request.model));
        body.insert("messages".into(), json!(request.messages));
        body.insert("max_tokens".into(), json!(request.max_tokens));
        body.insert("stream".into(), json!(true));
        if let Some(temperature) = request.temperature {
            body.insert("temperature".into(), json!(temperature));
        }

        let response = self
            .http
            .post(format!("{}/v1/chat/completions", self.base_url))
            .bearer_auth(&self.api_key)
            .json(&body)
            .send()
            .await
            .map_err(|e| ProviderError::Request(e.without_url().to_string()))?;

        if !response.status().is_success() {
            return Err(ProviderError::Status(response.status().as_u16()));
        }

        let (tx, rx) = tokio::sync::mpsc::channel(32);
        tokio::spawn(async move {
            let mut bytes = response.bytes_stream();
            let mut lines = LineBuffer::new();
            while let Some(chunk) = bytes.next().await {
                let chunk = match chunk {
                    Ok(c) => c,
                    Err(e) => {
                        let _ = tx
                            .send(Err(ProviderError::Request(e.without_url().to_string())))
                            .await;
                        return;
                    }
                };
                for line in lines.push(&chunk) {
                    if let Some(result) = parse_line(&line) {
                        let terminal = !matches!(result, Ok(StreamEvent::Delta(_)));
                        if tx.send(result).await.is_err() || terminal {
                            return;
                        }
                    }
                }
            }
            // Closed without `[DONE]`: truncated response, surface an error.
            let _ = tx
                .send(Err(ProviderError::Request(
                    "openai stream ended before [DONE]".into(),
                )))
                .await;
        });

        Ok(Box::pin(ReceiverStream::new(rx)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_delta() {
        let line = r#"data: {"choices":[{"delta":{"content":"Hel"}}]}"#;
        assert_eq!(parse_line(line), Some(Ok(StreamEvent::Delta("Hel".into()))));
    }

    #[test]
    fn parses_done() {
        assert_eq!(parse_line("data: [DONE]"), Some(Ok(StreamEvent::Done)));
    }

    #[test]
    fn surfaces_error_events() {
        let line = r#"data: {"error":{"type":"server_error","message":"boom"}}"#;
        assert!(matches!(parse_line(line), Some(Err(_))));
    }

    #[test]
    fn ignores_role_only_delta() {
        let line = r#"data: {"choices":[{"delta":{"role":"assistant"}}]}"#;
        assert_eq!(parse_line(line), None);
    }

    #[test]
    fn ignores_non_data_lines() {
        assert_eq!(parse_line(": keep-alive"), None);
        assert_eq!(parse_line(""), None);
    }
}
