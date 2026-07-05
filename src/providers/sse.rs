//! Minimal incremental parsers for streamed provider responses:
//! Server-Sent Events (`data: ...` lines) and newline-delimited JSON.

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
        lines
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
}
