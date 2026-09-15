use crate::{ClientBuilder, Error, ServerBuilder};
use std::{
    future::pending,
    io,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
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

#[tokio::test(start_paused = true)]
async fn oversized_client_timeout_fails_before_wrap_or_dial() {
    let client = ClientBuilder::default()
        .with_handshake_timeout(Duration::MAX)
        .build();
    let (stream, _peer) = tokio::io::duplex(16_384);
    let error = match client.wrap(stream).await {
        Err(error) => error,
        Ok(_) => panic!("oversized timeout unexpectedly succeeded"),
    };
    assert!(matches!(error, Error::IOError(error) if error.kind() == io::ErrorKind::InvalidInput));

    let client = ClientBuilder::default()
        .with_handshake_timeout(Duration::MAX)
        .build();
    let dial_polled = Arc::new(AtomicBool::new(false));
    let dial_marker = Arc::clone(&dial_polled);
    let dial = async move {
        dial_marker.store(true, Ordering::SeqCst);
        pending::<io::Result<DuplexStream>>().await
    };
    let result = client.establish(Box::pin(dial)).await;
    assert!(
        matches!(result, Err(Error::IOError(error)) if error.kind() == io::ErrorKind::InvalidInput)
    );
    assert!(!dial_polled.load(Ordering::SeqCst));
}

#[tokio::test(start_paused = true)]
async fn oversized_server_timeout_fails_before_session() {
    let server = ServerBuilder::<DuplexStream>::default()
        .with_handshake_timeout(Duration::MAX)
        .build();
    let (stream, _peer) = tokio::io::duplex(16_384);
    let error = match server.wrap(stream).await {
        Err(error) => error,
        Ok(_) => panic!("oversized timeout unexpectedly succeeded"),
    };
    assert!(matches!(error, Error::IOError(error) if error.kind() == io::ErrorKind::InvalidInput));
}
