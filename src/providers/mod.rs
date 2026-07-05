//! AI provider abstraction.
//!
//! The application only ever talks to `dyn ChatProvider`; which vendor is
//! behind it is a deployment decision. Adding a provider means implementing
//! the trait and registering it in [`build_provider`].

pub mod anthropic;
pub mod ollama;
pub mod openai;
pub mod sse;

use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;
use futures::Stream;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::config::{Config, ProviderKind};

#[derive(Debug, Error)]
pub enum ProviderError {
    #[error("provider request failed: {0}")]
    Request(String),

    #[error("provider returned status {0}")]
    Status(u16),

    #[error("provider response could not be parsed")]
    Parse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Clone)]
pub struct ChatRequest {
    pub model: String,
    pub messages: Vec<ChatMessage>,
    pub max_tokens: u32,
    pub temperature: Option<f32>,
}

/// One incremental piece of a streamed completion.
#[derive(Debug, Clone, PartialEq)]
pub enum StreamEvent {
    /// A chunk of response text.
    Delta(String),
    /// The provider signalled the end of the stream.
    Done,
}

pub type EventStream = Pin<Box<dyn Stream<Item = Result<StreamEvent, ProviderError>> + Send>>;

#[async_trait]
pub trait ChatProvider: Send + Sync {
    /// Stable provider identifier for logs and metrics (never exposed in the
    /// chat data path).
    fn name(&self) -> &'static str;

    /// Start a streaming completion. Prompt content flows through here in
    /// plaintext, in memory only — implementations must never log it.
    async fn stream_chat(&self, request: ChatRequest) -> Result<EventStream, ProviderError>;
}

/// Construct the configured provider.
pub fn build_provider(config: &Config) -> Arc<dyn ChatProvider> {
    let http = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("failed to build HTTP client");

    match config.provider {
        ProviderKind::OpenAi => Arc::new(openai::OpenAiProvider::new(
            http,
            config.openai_base_url.clone(),
            config.openai_api_key.clone().unwrap_or_default(),
        )),
        ProviderKind::Anthropic => Arc::new(anthropic::AnthropicProvider::new(
            http,
            config.anthropic_base_url.clone(),
            config.anthropic_api_key.clone().unwrap_or_default(),
        )),
        ProviderKind::Ollama => Arc::new(ollama::OllamaProvider::new(
            http,
            config.ollama_base_url.clone(),
        )),
    }
}
