#![no_main]
//! Fuzz the frame reader with arbitrary bytes.
//!
//! Verifies that `read_frame` never panics on any input — it should
//! always return `Ok(bytes)` or `Err(Error)`, never crash.

use libfuzzer_sys::fuzz_target;
use tokio::runtime::Runtime;

fuzz_target!(|data: &[u8]| {
    let rt = Runtime::new().expect("failed to create tokio runtime for fuzz target");
    rt.block_on(async {
        let mut cursor = std::io::Cursor::new(data.to_vec());
        // Should never panic — only Ok or Err
        let _ = zerolease::protocol::frame::read_frame(&mut cursor).await;
    });
});
