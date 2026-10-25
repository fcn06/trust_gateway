//! Standalone Rust example demonstrating how an agent or client interacts with
//! the Marketplace Trust Gateway via the MCP JSON-RPC protocol.

fn main() {
    println!("=== Marketplace Trust Gateway Rust Example ===");
    println!("To connect to the local gateway at http://127.0.0.1:8080:");
    println!("1. Start gateway: ./scripts/run_oss.sh");
    println!("2. Call tool: POST /v1/mcp/messages with method 'tools/call'");
    println!("Governing invariant: Agents propose. Gateway decides. Executors verify.");
}
