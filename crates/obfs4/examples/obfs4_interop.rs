//! Small bounded wire peer used by `tools/interop/run.py`.

use std::{env, error::Error, io};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use obfs4::{ClientBuilder, ServerBuilder, IAT};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const PAYLOAD_SIZE: usize = 4096;

#[tokio::main(worker_threads = 2)]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut args = env::args().skip(1);
    let mode = args.next().ok_or("missing mode")?;
    let mut addr = None;
    let mut cert = None;
    let mut iat = IAT::Off;
    let mut expect_failure = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--addr" => addr = Some(args.next().ok_or("missing --addr value")?),
            "--cert" => cert = Some(args.next().ok_or("missing --cert value")?),
            "--iat-mode" => iat = args.next().ok_or("missing --iat-mode value")?.parse()?,
            "--expect-failure" => expect_failure = true,
            other => return Err(format!("unknown argument {other}").into()),
        }
    }

    match mode.as_str() {
        "client" => {
            run_client(
                addr.ok_or("client requires --addr")?,
                cert.ok_or("client requires --cert")?,
                iat,
                expect_failure,
            )
            .await?
        }
        "server" => run_server(addr.unwrap_or_else(|| "127.0.0.1:0".into()), iat).await?,
        other => return Err(format!("unknown mode {other}").into()),
    }
    Ok(())
}

async fn run_client(
    addr: String,
    cert: String,
    iat: IAT,
    expect_failure: bool,
) -> Result<(), Box<dyn Error>> {
    let raw = STANDARD.decode(cert + "==")?;
    if raw.len() != 52 {
        return Err(format!("cert has {} decoded bytes, expected 52", raw.len()).into());
    }
    let node_id: [u8; 20] = raw[..20].try_into().expect("checked cert length");
    let pubkey: [u8; 32] = raw[20..].try_into().expect("checked cert length");
    let mut builder = ClientBuilder::default();
    builder
        .with_node_id(node_id)
        .with_node_pubkey(pubkey)
        .with_iat_mode(iat)
        .with_handshake_timeout(std::time::Duration::from_secs(5));
    let stream = TcpStream::connect(addr).await?;
    match builder.build().wrap(stream).await {
        Ok(_) if expect_failure => Err("malformed peer was accepted".into()),
        Ok(mut stream) => {
            client_exchange(&mut stream).await?;
            println!("OK");
            Ok(())
        }
        Err(_) if expect_failure => {
            println!("EXPECTED_FAILURE");
            Ok(())
        }
        Err(err) => Err(err.into()),
    }
}

async fn run_server(addr: String, iat: IAT) -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind(addr).await?;
    let mut builder = ServerBuilder::<TcpStream>::default();
    builder.iat_mode(iat);
    let server = builder.build();
    let cert = extract_cert(&server.client_params().as_opts())?;
    println!("READY {} {}", listener.local_addr()?, cert);
    let (socket, _) = listener.accept().await?;
    let mut stream = server.wrap(socket).await?;
    server_exchange(&mut stream).await?;
    println!("OK");
    Ok(())
}

fn extract_cert(options: &str) -> Result<String, io::Error> {
    ptrs::args::Args::parse_client_parameters(options)
        .map_err(io::Error::other)?
        .retrieve("cert")
        .filter(|cert| !cert.is_empty())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "client options have no cert"))
}

async fn server_exchange<T>(stream: &mut T) -> Result<(), io::Error>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let payload = vec![b'C'; PAYLOAD_SIZE];
    let mut got = vec![0; PAYLOAD_SIZE];
    stream.read_exact(&mut got).await?;
    if got != payload {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "client payload mismatch",
        ));
    }
    stream.write_all(&vec![b'S'; PAYLOAD_SIZE]).await?;
    stream.shutdown().await?;
    let extra = tokio::io::copy(stream, &mut tokio::io::sink()).await?;
    if extra != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected client payload",
        ));
    }
    Ok(())
}

async fn client_exchange<T>(stream: &mut T) -> Result<(), io::Error>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    stream.write_all(&vec![b'C'; PAYLOAD_SIZE]).await?;
    stream.flush().await?;
    let mut got = vec![0; PAYLOAD_SIZE];
    stream.read_exact(&mut got).await?;
    if got != vec![b'S'; PAYLOAD_SIZE] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "server reply mismatch",
        ));
    }
    stream.shutdown().await?;
    let extra = tokio::io::copy(stream, &mut tokio::io::sink()).await?;
    if extra != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected server payload",
        ));
    }
    Ok(())
}
