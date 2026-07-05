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
/// because a final line can carry both content and `done: true`.
pub(crate) fn parse_line(line: &str) -> Vec<StreamEvent> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
        return Vec::new();
    };
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
    events
}

#[async_trait]
impl ChatProvider for OllamaProvider {
    fn name(&self) -> &'static str {
        "ollama"
    }

    async fn stream_chat(&self, request: ChatRequest) -> Result<EventStream, ProviderError> {
        let body = json!({
            "model": request.model,
            "messages": request.messages,
            "stream": true,
            "options": {
                "num_predict": request.max_tokens,
                "temperature": request.temperature,
            },
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
                    for event in parse_line(&line) {
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
    fn parses_content_line() {
        let line =
            r#"{"model":"llama3.2","message":{"role":"assistant","content":"Hey"},"done":false}"#;
        assert_eq!(parse_line(line), vec![StreamEvent::Delta("Hey".into())]);
    }

    #[test]
    fn parses_done_line() {
        let line =
            r#"{"model":"llama3.2","message":{"role":"assistant","content":""},"done":true}"#;
        assert_eq!(parse_line(line), vec![StreamEvent::Done]);
    }

    #[test]
    fn final_line_with_content_and_done() {
        let line = r#"{"message":{"content":"!"},"done":true}"#;
        assert_eq!(
            parse_line(line),
            vec![StreamEvent::Delta("!".into()), StreamEvent::Done]
        );
    }

    #[test]
    fn ignores_garbage() {
        assert!(parse_line("not json").is_empty());
    }
}
