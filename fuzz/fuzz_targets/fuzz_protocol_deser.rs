#![no_main]
//! Fuzz protocol message deserialization with arbitrary bytes.
//!
//! Simulates a malicious client sending garbage data through the
//! protocol layer. Verifies that deserializing ClientHello, Request,
//! and Response types never panics.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Try to deserialize as each protocol message type.
    // None of these should ever panic.
    let _ = serde_json::from_slice::<zerolease::protocol::ClientHello>(data);
    let _ = serde_json::from_slice::<zerolease::protocol::ServerHello>(data);
    let _ = serde_json::from_slice::<zerolease::protocol::Request>(data);
    let _ = serde_json::from_slice::<zerolease::protocol::Response>(data);

    // Also try the method-specific param types
    let _ = serde_json::from_slice::<zerolease::protocol::StoreSecretRequest>(data);
    let _ = serde_json::from_slice::<zerolease::protocol::RequestLeaseRequest>(data);
    let _ = serde_json::from_slice::<zerolease::protocol::AccessSecretRequest>(data);
    let _ = serde_json::from_slice::<zerolease::protocol::RevokeLeaseRequest>(data);
    let _ = serde_json::from_slice::<zerolease::protocol::RenewLeaseRequest>(data);
    let _ = serde_json::from_slice::<zerolease::protocol::DeleteSecretRequest>(data);
});
