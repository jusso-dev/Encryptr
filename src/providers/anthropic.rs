//! Anthropic Messages API provider (SSE streaming).

use async_trait::async_trait;
use futures::StreamExt;
use serde_json::json;
use tokio_stream::wrappers::ReceiverStream;

use super::sse::{sse_data, LineBuffer};
use super::{ChatMessage, ChatProvider, ChatRequest, EventStream, ProviderError, StreamEvent};

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

/// Split a message list into Anthropic's top-level `system` prompt and the
/// `user`/`assistant` turns. The Messages API rejects `system` roles inside
/// `messages`, so any system content must be hoisted out.
fn split_system(messages: &[ChatMessage]) -> (Option<String>, Vec<serde_json::Value>) {
    let mut system_parts = Vec::new();
    let mut turns = Vec::new();
    for message in messages {
        if message.role == "system" {
            system_parts.push(message.content.clone());
        } else {
            turns.push(json!({ "role": message.role, "content": message.content }));
        }
    }
    let system = if system_parts.is_empty() {
        None
    } else {
        Some(system_parts.join("\n\n"))
    };
    (system, turns)
}

/// Parse one SSE line from the Anthropic stream. `None` means "ignore this
/// line"; `Some(Err)` surfaces a provider-signalled error.
pub(crate) fn parse_line(line: &str) -> Option<Result<StreamEvent, ProviderError>> {
    let data = sse_data(line)?;
    let value: serde_json::Value = serde_json::from_str(data).ok()?;
    match value.get("type")?.as_str()? {
        "content_block_delta" => {
            let text = value.get("delta")?.get("text")?.as_str()?;
            if text.is_empty() {
                None
            } else {
                Some(Ok(StreamEvent::Delta(text.to_string())))
            }
        }
        "message_stop" => Some(Ok(StreamEvent::Done)),
        // Anthropic emits `{"type":"error","error":{"type":..,"message":..}}`
        // mid-stream (e.g. overloaded_error). Surface it instead of silently
        // truncating the response and reporting success.
        "error" => {
            let kind = value
                .get("error")
                .and_then(|e| e.get("type"))
                .and_then(|t| t.as_str())
                .unwrap_or("unknown");
            Some(Err(ProviderError::Request(format!(
                "anthropic stream error: {kind}"
            ))))
        }
        _ => None,
    }
}

#[async_trait]
impl ChatProvider for AnthropicProvider {
    fn name(&self) -> &'static str {
        "anthropic"
    }

    async fn stream_chat(&self, request: ChatRequest) -> Result<EventStream, ProviderError> {
        let (system, messages) = split_system(&request.messages);
        let mut body = serde_json::Map::new();
        body.insert("model".into(), json!(request.model));
        body.insert("messages".into(), json!(messages));
        body.insert("max_tokens".into(), json!(request.max_tokens));
        body.insert("stream".into(), json!(true));
        // Only send `temperature` when the client set it — Anthropic rejects a
        // `null`, unlike a simply-absent field.
        if let Some(temperature) = request.temperature {
            body.insert("temperature".into(), json!(temperature));
        }
        if let Some(system) = system {
            body.insert("system".into(), json!(system));
        }

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
                    // A terminal event (Done) or a provider error ends the
                    // stream; forward it and stop.
                    if let Some(result) = parse_line(&line) {
                        let terminal = !matches!(result, Ok(StreamEvent::Delta(_)));
                        if tx.send(result).await.is_err() || terminal {
                            return;
                        }
                    }
                }
            }
            // Stream closed without a terminal event: the response was
            // truncated — report an error rather than a clean completion.
            let _ = tx
                .send(Err(ProviderError::Request(
                    "anthropic stream ended before message_stop".into(),
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
    fn parses_content_block_delta() {
        let line = r#"data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hi"}}"#;
        assert_eq!(parse_line(line), Some(Ok(StreamEvent::Delta("Hi".into()))));
    }

    #[test]
    fn parses_message_stop() {
        let line = r#"data: {"type":"message_stop"}"#;
        assert_eq!(parse_line(line), Some(Ok(StreamEvent::Done)));
    }

    #[test]
    fn surfaces_error_events() {
        let line =
            r#"data: {"type":"error","error":{"type":"overloaded_error","message":"overloaded"}}"#;
        assert!(matches!(parse_line(line), Some(Err(_))));
    }

    #[test]
    fn ignores_other_events() {
        let line = r#"data: {"type":"message_start","message":{}}"#;
        assert_eq!(parse_line(line), None);
        assert_eq!(parse_line("event: content_block_delta"), None);
    }

    #[test]
    fn hoists_system_messages() {
        let messages = vec![
            ChatMessage {
                role: "system".into(),
                content: "be terse".into(),
            },
            ChatMessage {
                role: "user".into(),
                content: "hi".into(),
            },
        ];
        let (system, turns) = split_system(&messages);
        assert_eq!(system.as_deref(), Some("be terse"));
        assert_eq!(turns.len(), 1);
        assert_eq!(turns[0]["role"], "user");
    }
}
