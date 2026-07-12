//! Ollama provider (newline-delimited JSON streaming).

use async_trait::async_trait;
use futures::StreamExt;
use serde_json::json;
use tokio_stream::wrappers::ReceiverStream;

use super::sse::LineBuffer;
use super::{ChatProvider, ChatRequest, EventStream, ProviderError, StreamEvent};

pub struct OllamaProvider {
    http: reqwest::Client,
    base_url: String,
}

impl OllamaProvider {
    pub fn new(http: reqwest::Client, base_url: String) -> Self {
        Self { http, base_url }
    }
}

/// Parse one NDJSON line from the Ollama stream. Returns up to two events
/// because a final line can carry both content and `done: true`. An `error`
/// field is surfaced as a provider error rather than silently ignored.
pub(crate) fn parse_line(line: &str) -> Result<Vec<StreamEvent>, ProviderError> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
        return Ok(Vec::new());
    };
    if let Some(error) = value.get("error").and_then(|e| e.as_str()) {
        // Keep the message short and non-sensitive (model/availability errors).
        let kind = error
            .split_whitespace()
            .take(6)
            .collect::<Vec<_>>()
            .join(" ");
        return Err(ProviderError::Request(format!(
            "ollama stream error: {kind}"
        )));
    }
    let mut events = Vec::new();
    if let Some(text) = value
        .get("message")
        .and_then(|m| m.get("content"))
        .and_then(|c| c.as_str())
    {
        if !text.is_empty() {
            events.push(StreamEvent::Delta(text.to_string()));
        }
    }
    if value.get("done").and_then(|d| d.as_bool()) == Some(true) {
        events.push(StreamEvent::Done);
    }
    Ok(events)
}

#[async_trait]
impl ChatProvider for OllamaProvider {
    fn name(&self) -> &'static str {
        "ollama"
    }

    async fn stream_chat(&self, request: ChatRequest) -> Result<EventStream, ProviderError> {
        let mut options = serde_json::Map::new();
        options.insert("num_predict".into(), json!(request.max_tokens));
        if let Some(temperature) = request.temperature {
            options.insert("temperature".into(), json!(temperature));
        }
        let body = json!({
            "model": request.model,
            "messages": request.messages,
            "stream": true,
            "options": options,
        });

        let response = self
            .http
            .post(format!("{}/api/chat", self.base_url))
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
            let mut saw_done = false;
            'outer: while let Some(chunk) = bytes.next().await {
                let chunk = match chunk {
                    Ok(c) => c,
                    Err(e) => {
                        let _ = tx
                            .send(Err(ProviderError::Request(e.without_url().to_string())))
                            .await;
                        return;
                    }
                };
                let mut pending = lines.push(&chunk);
                // Also flush any trailing record left without a newline once the
                // body ends — handled below after the read loop, but a chunk
                // boundary mid-record is covered by LineBuffer itself.
                pending.retain(|l| !l.is_empty());
                for line in pending {
                    match parse_line(&line) {
                        Ok(events) => {
                            for event in events {
                                let done = event == StreamEvent::Done;
                                if tx.send(Ok(event)).await.is_err() {
                                    return;
                                }
                                if done {
                                    saw_done = true;
                                    break 'outer;
                                }
                            }
                        }
                        Err(error) => {
                            let _ = tx.send(Err(error)).await;
                            return;
                        }
                    }
                }
            }
            // Parse any final unterminated record.
            if !saw_done {
                if let Some(line) = lines.flush() {
                    match parse_line(&line) {
                        Ok(events) => {
                            for event in events {
                                let done = event == StreamEvent::Done;
                                let _ = tx.send(Ok(event)).await;
                                if done {
                                    saw_done = true;
                                }
                            }
                        }
                        Err(error) => {
                            let _ = tx.send(Err(error)).await;
                            return;
                        }
                    }
                }
            }
            if !saw_done {
                let _ = tx
                    .send(Err(ProviderError::Request(
                        "ollama stream ended before done".into(),
                    )))
                    .await;
            }
        });

        Ok(Box::pin(ReceiverStream::new(rx)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_content_line() {
        let line =
            r#"{"model":"llama3.2","message":{"role":"assistant","content":"Hey"},"done":false}"#;
        assert_eq!(
            parse_line(line).unwrap(),
            vec![StreamEvent::Delta("Hey".into())]
        );
    }

    #[test]
    fn parses_done_line() {
        let line =
            r#"{"model":"llama3.2","message":{"role":"assistant","content":""},"done":true}"#;
        assert_eq!(parse_line(line).unwrap(), vec![StreamEvent::Done]);
    }

    #[test]
    fn final_line_with_content_and_done() {
        let line = r#"{"message":{"content":"!"},"done":true}"#;
        assert_eq!(
            parse_line(line).unwrap(),
            vec![StreamEvent::Delta("!".into()), StreamEvent::Done]
        );
    }

    #[test]
    fn surfaces_error_field() {
        let line = r#"{"error":"model 'llama3.2' not found"}"#;
        assert!(parse_line(line).is_err());
    }

    #[test]
    fn ignores_garbage() {
        assert!(parse_line("not json").unwrap().is_empty());
    }
}
