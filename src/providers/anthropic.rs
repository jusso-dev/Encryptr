//! Anthropic Messages API provider (SSE streaming).

use async_trait::async_trait;
use futures::StreamExt;
use serde_json::json;
use tokio_stream::wrappers::ReceiverStream;

use super::sse::{sse_data, LineBuffer};
use super::{ChatProvider, ChatRequest, EventStream, ProviderError, StreamEvent};

const API_VERSION: &str = "2023-06-01";

pub struct AnthropicProvider {
    http: reqwest::Client,
    base_url: String,
    api_key: String,
}

impl AnthropicProvider {
    pub fn new(http: reqwest::Client, base_url: String, api_key: String) -> Self {
        Self {
            http,
            base_url,
            api_key,
        }
    }
}

/// Parse one SSE line from the Anthropic stream.
pub(crate) fn parse_line(line: &str) -> Option<StreamEvent> {
    let data = sse_data(line)?;
    let value: serde_json::Value = serde_json::from_str(data).ok()?;
    match value.get("type")?.as_str()? {
        "content_block_delta" => {
            let text = value.get("delta")?.get("text")?.as_str()?;
            if text.is_empty() {
                None
            } else {
                Some(StreamEvent::Delta(text.to_string()))
            }
        }
        "message_stop" => Some(StreamEvent::Done),
        _ => None,
    }
}

#[async_trait]
impl ChatProvider for AnthropicProvider {
    fn name(&self) -> &'static str {
        "anthropic"
    }

    async fn stream_chat(&self, request: ChatRequest) -> Result<EventStream, ProviderError> {
        let body = json!({
            "model": request.model,
            "messages": request.messages,
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
            "stream": true,
        });

        let response = self
            .http
            .post(format!("{}/v1/messages", self.base_url))
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", API_VERSION)
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
                    if let Some(event) = parse_line(&line) {
                        let done = event == StreamEvent::Done;
                        if tx.send(Ok(event)).await.is_err() || done {
                            return;
                        }
                    }
                }
            }
            let _ = tx.send(Ok(StreamEvent::Done)).await;
        });

        Ok(Box::pin(ReceiverStream::new(rx)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_content_block_delta() {
        let line = r#"data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hi"}}"#;
        assert_eq!(parse_line(line), Some(StreamEvent::Delta("Hi".into())));
    }

    #[test]
    fn parses_message_stop() {
        let line = r#"data: {"type":"message_stop"}"#;
        assert_eq!(parse_line(line), Some(StreamEvent::Done));
    }

    #[test]
    fn ignores_other_events() {
        let line = r#"data: {"type":"message_start","message":{}}"#;
        assert_eq!(parse_line(line), None);
        assert_eq!(parse_line("event: content_block_delta"), None);
    }
}
