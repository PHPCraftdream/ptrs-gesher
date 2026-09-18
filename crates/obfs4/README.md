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

Version `0.6.0` requires Rust 1.89 or newer. See the
[migration guide](https://github.com/PHPCraftdream/ptrs-gesher/blob/v0.6.0/docs/MIGRATING-0.6.md)
for state-file and fallible configuration APIs.
Not production ready; do not rely on this for security-critical
applications.

## Example

Client example using the `ptrs-gesher-core` trait framework:

```rust ignore
use ptrs::Args;
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

Server example:

```rust ignore
let message = b"Hello universe";
let (mut c, mut s) = tokio::io::duplex(65_536);
let mut rng = rand::thread_rng();

let o4_server = obfs4::Server::new_from_random(&mut rng);

tokio::spawn(async move {
    let mut o4s_stream = o4_server.wrap(&mut s).await.unwrap();

    let mut buf = [0_u8; 50];
    let n = o4s_stream.read(&mut buf).await.unwrap();

    // echo the message back over the tunnel
    o4s_stream.write_all(&buf[..n]).await.unwrap();
});
```

## License

Dual-licensed under either:

- Apache License, Version 2.0
- MIT license

at your option.
