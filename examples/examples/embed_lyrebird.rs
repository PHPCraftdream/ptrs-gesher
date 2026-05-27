//! Skeleton showing how a parent application would embed the lyrebird
//! PT-manager loop as a library.
//!
//! In a real deployment, Tor (or arti) launches the PT binary and communicates
//! via `TOR_PT_*` environment variables and a stdout/stdin control channel.
//! When embedding lyrebird as a library you set those env vars yourself and
//! then call `lyrebird::run().await`. This example shows the required env
//! vars and the call site, but does NOT actually run the loop (it would block
//! waiting for a Tor parent that is not there).
//!
//! Run with:
//!   cargo run -p ptrs-gesher-examples --features embed-lyrebird --example embed_lyrebird

fn main() {
    println!("=== Embedding lyrebird as a library ===\n");

    // --- Required environment variables (PT spec) ---
    // These are normally set by the Tor daemon before exec()-ing the PT binary.
    // When embedding, you must set them yourself.
    let required_env = [
        (
            "TOR_PT_MANAGED_TRANSPORT_VER",
            "1",
            "Protocol version (always \"1\")",
        ),
        (
            "TOR_PT_STATE_LOCATION",
            "/tmp/pt_state/",
            "Directory where the PT may store persistent state",
        ),
        (
            "TOR_PT_CLIENT_TRANSPORTS",
            "obfs4,webtunnel",
            "Comma-separated list of transports the parent wants",
        ),
    ];

    println!("Required TOR_PT_* environment variables for client mode:\n");
    for (key, example, description) in &required_env {
        println!("  {key}={example}");
        println!("    {description}\n");
    }

    // --- The actual embedding call ---
    println!("To actually run the PT loop:\n");
    println!("    // Set env vars, then:");
    println!("    lyrebird::run().await?;\n");
    println!("This blocks until the parent process signals shutdown (via");
    println!("stdin EOF or SIGTERM).\n");

    // Demonstrate that the lyrebird crate is reachable.
    let creds = Some(("cert=AAA".to_string(), ";iat-mode=0".to_string()));
    let arg_string = lyrebird::arg_string_from_creds(creds);
    println!("Smoke-check: arg_string_from_creds -> \"{arg_string}\"");
    assert_eq!(arg_string, "cert=AAA;iat-mode=0");

    println!("\nOK: lyrebird crate is linked and callable.");
}
