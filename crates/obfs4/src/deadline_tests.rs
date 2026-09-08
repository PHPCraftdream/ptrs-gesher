use crate::{ClientBuilder, Error, ServerBuilder};
use std::{future::pending, io, time::Duration};
use tokio::{io::DuplexStream, time::Instant};

#[tokio::test(start_paused = true)]
async fn client_absolute_deadline_survives_build_and_delayed_use() {
    let deadline = Instant::now() + Duration::from_secs(5);
    let client = ClientBuilder::default()
        .with_handshake_deadline(deadline)
        .build();
    tokio::time::advance(Duration::from_secs(3)).await;
    let (stream, _peer) = tokio::io::duplex(16_384);
    assert!(matches!(
        client.wrap(stream).await,
        Err(Error::HandshakeTimeout)
    ));
    assert_eq!(Instant::now(), deadline);
}

#[tokio::test(start_paused = true)]
async fn server_absolute_deadline_survives_build_and_delayed_use() {
    let deadline = Instant::now() + Duration::from_secs(5);
    let server = ServerBuilder::<DuplexStream>::default()
        .with_handshake_deadline(deadline)
        .build();
    tokio::time::advance(Duration::from_secs(3)).await;
    let (stream, _peer) = tokio::io::duplex(16_384);
    assert!(matches!(
        server.wrap(stream).await,
        Err(Error::HandshakeTimeout)
    ));
    assert_eq!(Instant::now(), deadline);
}

#[tokio::test(start_paused = true)]
async fn expired_deadline_does_not_restart_the_default_timeout() {
    let deadline = Instant::now() - Duration::from_secs(1);
    let client = ClientBuilder::default()
        .with_handshake_deadline(deadline)
        .build();
    let before = Instant::now();
    let (stream, _peer) = tokio::io::duplex(16_384);
    assert!(matches!(
        client.wrap(stream).await,
        Err(Error::HandshakeTimeout)
    ));
    assert_eq!(Instant::now(), before);
}

#[tokio::test(start_paused = true)]
async fn deadline_also_bounds_a_pending_dial() {
    let client = ClientBuilder::default()
        .with_handshake_timeout(Duration::from_secs(5))
        .build();
    let before = Instant::now();
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        client.establish(Box::pin(pending::<io::Result<DuplexStream>>())),
    )
    .await;
    assert!(matches!(result, Ok(Err(Error::HandshakeTimeout))));
    assert_eq!(Instant::now() - before, Duration::from_secs(5));
}

#[tokio::test(start_paused = true)]
async fn transport_builder_timeout_is_effective() {
    let mut builder = ClientBuilder::default();
    <ClientBuilder as ptrs::ClientBuilder<DuplexStream>>::timeout(
        &mut builder,
        Some(Duration::from_secs(3)),
    )
    .unwrap();
    let before = Instant::now();
    let (stream, _peer) = tokio::io::duplex(16_384);
    assert!(matches!(
        builder.build().wrap(stream).await,
        Err(Error::HandshakeTimeout)
    ));
    assert_eq!(Instant::now() - before, Duration::from_secs(3));
}
