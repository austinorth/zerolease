#![no_main]
//! Fuzz DomainScope pattern matching with arbitrary strings.
//!
//! Verifies that `DomainScope::matches` never panics on any input,
//! including Unicode, control characters, and extremely long strings.

use libfuzzer_sys::fuzz_target;
use zerolease::types::DomainScope;

fuzz_target!(|data: &[u8]| {
    // Use the raw bytes as two strings: a pattern and a host
    if data.len() < 2 {
        return;
    }
    let split = data.len() / 2;

    // Try UTF-8 conversion — if it fails, that's fine (not a string)
    if let (Ok(pattern), Ok(host)) = (
        std::str::from_utf8(&data[..split]),
        std::str::from_utf8(&data[split..]),
    ) {
        let scope = DomainScope::new(pattern);
        // Should never panic
        let _ = scope.matches(host);
    }
});
