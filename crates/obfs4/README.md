# ptrs-gesher-obfs4

<p>
  <a href="https://crates.io/crates/ptrs-gesher-obfs4">
    <img src="https://img.shields.io/crates/v/ptrs-gesher-obfs4.svg">
  </a>
  <a href="https://docs.rs/ptrs-gesher-obfs4">
    <img src="https://docs.rs/ptrs-gesher-obfs4/badge.svg">
  </a>
  <a href="https://github.com/PHPCraftdream/ptrs-gesher">
    <img src="https://img.shields.io/badge/license-MIT%2FApache--2.0-blue" alt="License: MIT/Apache 2.0">
  </a>
</p>

An implementation of the obfs4 pluggable transport in pure Rust,
providing both client and server sides. Part of the
[ptrs-gesher](https://github.com/PHPCraftdream/ptrs-gesher) framework.

## Status

The current crate requires Rust 1.92 or newer. See the
[migration guide](https://github.com/PHPCraftdream/ptrs-gesher/blob/v0.6.0/docs/MIGRATING-0.6.md)
for state-file and fallible configuration APIs.
Not production ready; do not rely on this for security-critical
applications.

## Example

Client example using the `ptrs-gesher-core` trait framework:

```rust ignore
// Illustrative only: placeholder certificate and omitted async runtime / crate
// prerequisites; replace with a real bridge certificate in an async application.
use ptrs::args::Args;
use obfs4;
use tokio::net::TcpStream;

let mut args = Args::new();
args.add("cert", "<certificate from the bridge line>");
args.add("iat-mode", "0");
let client = obfs4::ClientBuilder::from_params(vec![args.encode_client_parameters().into_bytes()])?
    .try_build()?;

// future that opens a tcp connection when awaited
let conn_future = TcpStream::connect("127.0.0.1:9000");

// await (create) the tcp conn, attempt to handshake, and return a
// wrapped Read/Write object on success.
let obfs4_conn = client.establish(Box::pin(conn_future)).await?;
```

The snippet illustrates a server handler; a client must complete the obfs4 handshake before data is exchanged.

```rust no_run
use obfs4::Server;
use rand::thread_rng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:9000").await?;
    let mut rng = thread_rng();
    let server = Server::new_from_random(&mut rng);

    let (mut socket, _) = listener.accept().await?;
    let mut stream = server.wrap(&mut socket).await?;
    let mut buf = [0_u8; 1024];
    let n = stream.read(&mut buf).await?;
    stream.write_all(&buf[..n]).await?;
    Ok(())
}
```


## License

Dual-licensed under either:

- Apache License, Version 2.0
- MIT license

at your option.
