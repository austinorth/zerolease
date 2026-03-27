//! Length-prefixed frame encoding and decoding.
//!
//! Every message on the wire is a 4-byte big-endian length prefix
//! followed by that many bytes of payload. The framing layer knows
//! nothing about JSON or protocol types — it operates on raw bytes.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{Error, Result};

/// Maximum frame payload size: 1 MiB.
const MAX_FRAME_SIZE: u32 = 1_048_576;

/// Read a length-prefixed frame from a stream.
///
/// Note: EOF errors use more specific messages than the spec ("unexpected EOF
/// reading frame length" / "...frame payload") for easier debugging. The spec
/// says "unexpected EOF reading frame" generically.
///
/// Returns the raw payload bytes. Returns an error if:
/// - The declared length exceeds `MAX_FRAME_SIZE`
/// - The stream ends before the full frame is read
/// - An I/O error occurs
pub async fn read_frame(reader: &mut (impl AsyncRead + Unpin)) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            Error::Transport("unexpected EOF reading frame length".into())
        } else {
            Error::Transport(format!("failed to read frame length: {e}"))
        }
    })?;

    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME_SIZE {
        return Err(Error::Transport(format!(
            "frame too large: {len} bytes (max {MAX_FRAME_SIZE})"
        )));
    }

    let mut buf = vec![0u8; len as usize];
    reader.read_exact(&mut buf).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            Error::Transport("unexpected EOF reading frame payload".into())
        } else {
            Error::Transport(format!("failed to read frame payload: {e}"))
        }
    })?;

    Ok(buf)
}

/// Write a length-prefixed frame to a stream.
///
/// Returns an error if the payload exceeds `MAX_FRAME_SIZE` or
/// an I/O error occurs.
pub async fn write_frame(writer: &mut (impl AsyncWrite + Unpin), data: &[u8]) -> Result<()> {
    let len = data.len();
    if len > MAX_FRAME_SIZE as usize {
        return Err(Error::Transport(format!(
            "frame too large: {len} bytes (max {MAX_FRAME_SIZE})"
        )));
    }

    let len_buf = (len as u32).to_be_bytes();
    writer
        .write_all(&len_buf)
        .await
        .map_err(|e| Error::Transport(format!("failed to write frame length: {e}")))?;
    writer
        .write_all(data)
        .await
        .map_err(|e| Error::Transport(format!("failed to write frame payload: {e}")))?;
    writer
        .flush()
        .await
        .map_err(|e| Error::Transport(format!("failed to flush frame: {e}")))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use tokio::io::duplex;

    use super::*;

    #[tokio::test]
    async fn round_trip() {
        let (mut client, mut server) = duplex(1024);
        let payload = b"hello, zerolease";

        write_frame(&mut client, payload).await.expect("should write frame");
        let received = read_frame(&mut server).await.expect("should read frame");
        assert_eq!(received, payload);
    }

    #[tokio::test]
    async fn multiple_frames() {
        let (mut client, mut server) = duplex(4096);

        write_frame(&mut client, b"one")
            .await
            .expect("should write first frame");
        write_frame(&mut client, b"two")
            .await
            .expect("should write second frame");
        write_frame(&mut client, b"three")
            .await
            .expect("should write third frame");

        assert_eq!(read_frame(&mut server).await.expect("should read first frame"), b"one");
        assert_eq!(read_frame(&mut server).await.expect("should read second frame"), b"two");
        assert_eq!(
            read_frame(&mut server).await.expect("should read third frame"),
            b"three"
        );
    }

    #[tokio::test]
    async fn oversized_write_rejected() {
        let (mut client, _server) = duplex(1024);
        let huge = vec![0u8; MAX_FRAME_SIZE as usize + 1];

        let result = write_frame(&mut client, &huge).await;
        assert!(result.is_err());
        let err = result.expect_err("should reject oversized write").to_string();
        assert!(err.contains("frame too large"), "error was: {err}");
    }

    #[tokio::test]
    async fn oversized_read_rejected() {
        let (mut client, mut server) = duplex(1024);

        // Manually write a length header claiming a huge payload
        let fake_len = (MAX_FRAME_SIZE + 1).to_be_bytes();
        use tokio::io::AsyncWriteExt;
        client
            .write_all(&fake_len)
            .await
            .expect("should write fake length header");

        let result = read_frame(&mut server).await;
        assert!(result.is_err());
        let err = result.expect_err("should reject oversized read").to_string();
        assert!(err.contains("frame too large"), "error was: {err}");
    }

    #[tokio::test]
    async fn empty_frame_round_trip() {
        let (mut client, mut server) = duplex(1024);

        write_frame(&mut client, b"").await.expect("should write empty frame");
        let received = read_frame(&mut server).await.expect("should read empty frame");
        assert!(received.is_empty());
    }
}
