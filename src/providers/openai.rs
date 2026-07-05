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

/// Parse one SSE line from the OpenAI stream.
pub(crate) fn parse_line(line: &str) -> Option<StreamEvent> {
    let data = sse_data(line)?;
    if data == "[DONE]" {
        return Some(StreamEvent::Done);
    }
    let value: serde_json::Value = serde_json::from_str(data).ok()?;
    let delta = value
        .get("choices")?
        .get(0)?
        .get("delta")?
        .get("content")?
        .as_str()?;
    if delta.is_empty() {
        return None;
    }
    Some(StreamEvent::Delta(delta.to_string()))
}

#[async_trait]
impl ChatProvider for OpenAiProvider {
    fn name(&self) -> &'static str {
        "openai"
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
    fn parses_delta() {
        let line = r#"data: {"choices":[{"delta":{"content":"Hel"}}]}"#;
        assert_eq!(parse_line(line), Some(StreamEvent::Delta("Hel".into())));
    }

    #[test]
    fn parses_done() {
        assert_eq!(parse_line("data: [DONE]"), Some(StreamEvent::Done));
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
