//! Minimal incremental parsers for streamed provider responses:
//! Server-Sent Events (`data: ...` lines) and newline-delimited JSON.

/// A partial line that exceeds this bound is discarded rather than buffered
/// without limit — a misbehaving provider streaming newline-free bytes must
/// not be able to grow our memory unboundedly. Generous for any real SSE/JSON
/// line.
const MAX_LINE_BYTES: usize = 1024 * 1024;

/// Incremental line splitter over a byte stream. Feed chunks as they arrive;
/// complete lines come back with the trailing `\n` (and any `\r`) stripped.
#[derive(Default)]
pub struct LineBuffer {
    buffer: Vec<u8>,
}

impl LineBuffer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, chunk: &[u8]) -> Vec<String> {
        self.buffer.extend_from_slice(chunk);
        let mut lines = Vec::new();
        while let Some(pos) = self.buffer.iter().position(|&b| b == b'\n') {
            let mut line: Vec<u8> = self.buffer.drain(..=pos).collect();
            line.pop(); // '\n'
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            lines.push(String::from_utf8_lossy(&line).into_owned());
        }
        // Safety valve: never let an unterminated line grow without bound.
        if self.buffer.len() > MAX_LINE_BYTES {
            self.buffer.clear();
        }
        lines
    }

    /// Return any trailing bytes left in the buffer as a final line. Call at
    /// end-of-stream: some providers (e.g. Ollama NDJSON) may emit the last
    /// record without a trailing newline.
    pub fn flush(&mut self) -> Option<String> {
        if self.buffer.is_empty() {
            return None;
        }
        let mut line = std::mem::take(&mut self.buffer);
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        if line.is_empty() {
            return None;
        }
        Some(String::from_utf8_lossy(&line).into_owned())
    }
}

/// Extract the payload of an SSE `data:` line, if this line is one.
pub fn sse_data(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("data:")?;
    Some(rest.strip_prefix(' ').unwrap_or(rest))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_lines_across_chunks() {
        let mut buf = LineBuffer::new();
        assert_eq!(buf.push(b"data: hel"), Vec::<String>::new());
        assert_eq!(
            buf.push(b"lo\ndata: world\n"),
            vec!["data: hello", "data: world"]
        );
    }

    #[test]
    fn strips_carriage_returns() {
        let mut buf = LineBuffer::new();
        assert_eq!(
            buf.push(b"line one\r\nline two\r\n"),
            vec!["line one", "line two"]
        );
    }

    #[test]
    fn sse_data_extraction() {
        assert_eq!(sse_data("data: {\"x\":1}"), Some("{\"x\":1}"));
        assert_eq!(sse_data("data:{\"x\":1}"), Some("{\"x\":1}"));
        assert_eq!(sse_data("event: ping"), None);
        assert_eq!(sse_data(""), None);
        assert_eq!(sse_data("data: [DONE]"), Some("[DONE]"));
    }

    #[test]
    fn handles_empty_lines() {
        let mut buf = LineBuffer::new();
        assert_eq!(buf.push(b"\n\ndata: x\n"), vec!["", "", "data: x"]);
    }

    #[test]
    fn flush_returns_trailing_unterminated_line() {
        let mut buf = LineBuffer::new();
        assert_eq!(buf.push(b"{\"done\":true}"), Vec::<String>::new());
        assert_eq!(buf.flush().as_deref(), Some("{\"done\":true}"));
        // Second flush is empty.
        assert_eq!(buf.flush(), None);
    }

    #[test]
    fn oversized_unterminated_line_is_dropped() {
        let mut buf = LineBuffer::new();
        let huge = vec![b'a'; MAX_LINE_BYTES + 1];
        assert!(buf.push(&huge).is_empty());
        // The garbage was discarded, so a following complete line still parses.
        assert_eq!(buf.push(b"data: ok\n"), vec!["data: ok"]);
    }
}
