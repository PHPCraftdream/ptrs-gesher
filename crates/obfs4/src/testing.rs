use crate::{test_utils::init_subscriber, Result, Server};

use ptrs::{debug, trace};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use std::cmp::Ordering;
use std::time::Duration;

/// Guard against a wedged transfer in the echo tests below — a ceiling, never
/// an assertion about latency. None of these tests claims anything about how
/// fast a read completes; the timeout exists only so a genuinely stuck stream
/// fails instead of hanging the suite forever.
///
/// It is deliberately generous. The budget used to be 1s (2s in one test), and
/// on a loaded machine the very first read of `transfer_10k_x3` missed it —
/// "client failed to read after 0 iterations: timeout" — failing a transfer
/// that was merely slow to get scheduled, not broken. A tight wall-clock bound
/// in a test that does not measure time is a flake generator, so every echo
/// test now shares this one.
const READ_STALL_GUARD: Duration = Duration::from_secs(30);

#[tokio::test]
async fn public_handshake() -> Result<()> {
    init_subscriber();
    let (mut c, mut s) = tokio::io::duplex(65_536);
    let mut rng = rand::thread_rng();

    let o4_server = Server::new_from_random(&mut rng);
    let client_config = o4_server.client_params();

    tokio::spawn(async move {
        let o4s_stream = o4_server.wrap(&mut s).await.unwrap();
        let _ = tokio::io::split(o4s_stream);
    });

    let o4_client = client_config.build();
    let _o4c_stream = o4_client.wrap(&mut c).await?;

    Ok(())
}

#[tokio::test]
async fn public_iface() -> Result<()> {
    init_subscriber();
    let message = b"awoewaeojawenwaefaw lfawn;awe da;wfenalw fawf aw";
    let (mut c, mut s) = tokio::io::duplex(65_536);
    let mut rng = rand::thread_rng();

    let o4_server = Server::new_from_random(&mut rng);
    let client_config = o4_server.client_params();

    tokio::spawn(async move {
        let mut o4s_stream = o4_server.wrap(&mut s).await.unwrap();
        // let (mut r, mut w) = tokio::io::split(o4s_stream);
        // tokio::io::copy(&mut r, &mut w).await.unwrap();

        let mut buf = [0_u8; 50];
        let n = o4s_stream.read(&mut buf).await.unwrap();
        o4s_stream.write_all(&buf[..n]).await.unwrap();
        o4s_stream.flush().await.unwrap();

        if n != 48 {
            debug!("echo lengths don't match {n} != 48");
        }
    });

    let o4_client = client_config.build();
    let mut o4c_stream = o4_client.wrap(&mut c).await?;

    o4c_stream.write_all(&message[..]).await?;
    o4c_stream.flush().await?;

    let mut buf = vec![0_u8; message.len()];
    let n = o4c_stream.read(&mut buf).await?;
    assert_eq!(n, message.len());
    assert_eq!(
        &message[..],
        &buf,
        "\"{}\" != \"{}\"",
        String::from_utf8(message.to_vec())?,
        String::from_utf8(buf.clone())?,
    );

    Ok(())
}

/// Deterministic payload: the byte at offset `i` is a function of `i`, so an
/// echoed stream that loses, duplicates, reorders, or corrupts any byte fails
/// the content check in the test below, not only the length check.
fn payload_byte(offset: usize) -> u8 {
    (offset.wrapping_mul(31) ^ (offset >> 3)) as u8
}

fn payload(total: usize) -> Vec<u8> {
    (0..total).map(payload_byte).collect()
}

#[allow(non_snake_case)]
#[tokio::test]
async fn transfer_10k_x1() -> Result<()> {
    init_subscriber();

    let (c, mut s) = tokio::io::duplex(1024 * 1000);
    let mut rng = rand::thread_rng();

    let o4_server = Server::new_from_random(&mut rng);
    let client_config = o4_server.client_params();

    // Keep the handle: a panic or error inside the echo task must surface in
    // the test result, and the task must be joined instead of dangling.
    let echo: tokio::task::JoinHandle<Result<u64>> = tokio::spawn(async move {
        let o4s_stream = o4_server.wrap(&mut s).await?;
        let (mut r, mut w) = tokio::io::split(o4s_stream);
        let copied = tokio::io::copy(&mut r, &mut w).await?;
        w.flush().await?;
        Ok(copied)
    });

    let o4_client = client_config.build();
    let o4c_stream = o4_client.wrap(c).await?;

    let expected_total = 10240;
    let expected = payload(expected_total);

    // Writer and reader poll concurrently on the split halves, and the whole
    // observable transfer sits under one deadline — a sleep recreated per
    // read only bounds that single read, not the transfer. Both halves live
    // in this test task, so the oracle below is observed by the test itself;
    // nothing is delegated to a detached task.
    let transfer = tokio::time::timeout(READ_STALL_GUARD, async move {
        let (mut r, mut w) = tokio::io::split(o4c_stream);

        let writer = async {
            w.write_all(&expected).await?;
            w.flush().await?;
            Ok::<_, std::io::Error>(())
        };

        let mut received = vec![0_u8; expected_total];
        let reader = async {
            let mut off = 0;
            while off < received.len() {
                let n = r.read(&mut received[off..]).await?;
                if n == 0 {
                    // EOF before the full echo: fail now with the progress
                    // made instead of looping on zero-byte reads.
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        format!("echo ended after {off}/{} bytes", received.len()),
                    ));
                }
                off += n;
                trace!("received: {n}: total:{off}");
            }
            Ok::<_, std::io::Error>(())
        };

        tokio::try_join!(writer, reader)?;

        if let Some(off) = received
            .iter()
            .zip(expected.iter())
            .position(|(got, want)| got != want)
        {
            panic!(
                "echo content mismatch at offset {off}: sent {}, got {}",
                expected[off], received[off]
            );
        }
        Ok::<_, std::io::Error>(())
    })
    .await;

    let transfer = match transfer {
        Ok(result) => result,
        // The deadline fired on a wedged transfer, so the echo task is wedged
        // with it: panic without joining and let runtime teardown drop it.
        Err(_) => panic!("transfer did not finish within {READ_STALL_GUARD:?}"),
    };

    // The echo task sees EOF once the split halves above are dropped at the
    // end of the transfer block, so this join cannot hang on any path that
    // reaches it.
    let echoed = echo.await.expect("echo task panicked")?;
    assert_eq!(
        echoed, expected_total as u64,
        "echo task copied {echoed} bytes, expected {expected_total}"
    );

    transfer?;
    Ok(())
}

#[allow(non_snake_case)]
#[tokio::test]
async fn transfer_10k_x3() -> Result<()> {
    init_subscriber();

    let (c, mut s) = tokio::io::duplex(1024 * 1000);

    let o4_server = Server::getrandom();
    let client_config = o4_server.client_params();

    // Keep the handle: see `transfer_10k_x1`.
    let echo: tokio::task::JoinHandle<Result<u64>> = tokio::spawn(async move {
        let o4s_stream = o4_server.wrap(&mut s).await?;
        let (mut r, mut w) = tokio::io::split(o4s_stream);
        let copied = tokio::io::copy(&mut r, &mut w).await?;
        w.flush().await?;
        Ok(copied)
    });

    let o4_client = client_config.build();
    let o4c_stream = o4_client.wrap(c).await?;

    let expected_total = 10240 * 3;
    let expected = payload(expected_total);

    // Same shape as `transfer_10k_x1`, but the payload goes out as three
    // separately flushed messages, so every message carries different bytes.
    let transfer = tokio::time::timeout(READ_STALL_GUARD, async move {
        let (mut r, mut w) = tokio::io::split(o4c_stream);

        let writer = async {
            for chunk in expected.chunks(10240) {
                w.write_all(chunk).await?;
                w.flush().await?;
            }
            Ok::<_, std::io::Error>(())
        };

        let mut received = vec![0_u8; expected_total];
        let reader = async {
            let mut off = 0;
            while off < received.len() {
                let n = r.read(&mut received[off..]).await?;
                if n == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        format!("echo ended after {off}/{} bytes", received.len()),
                    ));
                }
                off += n;
                trace!("received: {n}: total:{off}");
            }
            Ok::<_, std::io::Error>(())
        };

        tokio::try_join!(writer, reader)?;

        if let Some(off) = received
            .iter()
            .zip(expected.iter())
            .position(|(got, want)| got != want)
        {
            panic!(
                "echo content mismatch at offset {off}: sent {}, got {}",
                expected[off], received[off]
            );
        }
        Ok::<_, std::io::Error>(())
    })
    .await;

    let transfer = match transfer {
        Ok(result) => result,
        Err(_) => panic!("transfer did not finish within {READ_STALL_GUARD:?}"),
    };

    let echoed = echo.await.expect("echo task panicked")?;
    assert_eq!(
        echoed, expected_total as u64,
        "echo task copied {echoed} bytes, expected {expected_total}"
    );

    transfer?;
    Ok(())
}

#[allow(non_snake_case)]
#[tokio::test]
async fn transfer_1M_1024x1024() -> Result<()> {
    init_subscriber();

    let (c, mut s) = tokio::io::duplex(1024 * 1000);
    let mut rng = rand::thread_rng();

    let o4_server = Server::new_from_random(&mut rng);
    let client_config = o4_server.client_params();

    // Keep the handle: see `transfer_10k_x1`.
    let echo: tokio::task::JoinHandle<Result<u64>> = tokio::spawn(async move {
        let o4s_stream = o4_server.wrap(&mut s).await?;
        let (mut r, mut w) = tokio::io::split(o4s_stream);
        let copied = tokio::io::copy(&mut r, &mut w).await?;
        w.flush().await?;
        Ok(copied)
    });

    let o4_client = client_config.build();
    let o4c_stream = o4_client.wrap(c).await?;

    let expected_total = 1024 * 1024;
    let expected = payload(expected_total);

    // Same shape as `transfer_10k_x1`, but written as 1024 separately flushed
    // 1 KiB writes, so successive writes carry different bytes.
    let transfer = tokio::time::timeout(READ_STALL_GUARD, async move {
        let (mut r, mut w) = tokio::io::split(o4c_stream);

        let writer = async {
            for chunk in expected.chunks(1024) {
                w.write_all(chunk).await?;
                w.flush().await?;
            }
            Ok::<_, std::io::Error>(())
        };

        let mut received = vec![0_u8; expected_total];
        let reader = async {
            let mut off = 0;
            while off < received.len() {
                let n = r.read(&mut received[off..]).await?;
                if n == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        format!("echo ended after {off}/{} bytes", received.len()),
                    ));
                }
                off += n;
                trace!("received: {n}: total:{off}");
            }
            Ok::<_, std::io::Error>(())
        };

        tokio::try_join!(writer, reader)?;

        if let Some(off) = received
            .iter()
            .zip(expected.iter())
            .position(|(got, want)| got != want)
        {
            panic!(
                "echo content mismatch at offset {off}: sent {}, got {}",
                expected[off], received[off]
            );
        }
        Ok::<_, std::io::Error>(())
    })
    .await;

    let transfer = match transfer {
        Ok(result) => result,
        Err(_) => panic!("transfer did not finish within {READ_STALL_GUARD:?}"),
    };

    let echoed = echo.await.expect("echo task panicked")?;
    assert_eq!(
        echoed, expected_total as u64,
        "echo task copied {echoed} bytes, expected {expected_total}"
    );

    transfer?;
    Ok(())
}

#[allow(non_snake_case)]
#[tokio::test]
async fn transfer_512k_x1() -> Result<()> {
    init_subscriber();

    let (c, mut s) = tokio::io::duplex(1024 * 512);
    let mut rng = rand::thread_rng();

    let o4_server = Server::new_from_random(&mut rng);
    let client_config = o4_server.client_params();

    // Keep the handle: see `transfer_10k_x1`.
    let echo: tokio::task::JoinHandle<Result<u64>> = tokio::spawn(async move {
        let o4s_stream = o4_server.wrap(&mut s).await?;
        let (mut r, mut w) = tokio::io::split(o4s_stream);
        let copied = tokio::io::copy(&mut r, &mut w).await?;
        w.flush().await?;
        Ok(copied)
    });

    let o4_client = client_config.build();
    let o4c_stream = o4_client.wrap(c).await?;

    let expected_total = 1024 * 512;
    let expected = payload(expected_total);

    // The reader is part of the observed transfer, not a detached task. The
    // duplex buffer is no larger than the payload and obfs4 framing makes the
    // ciphertext bigger, so a sequential write-then-read would deadlock and
    // the halves must be polled concurrently — but under `try_join!`, in this
    // test task, where the oracle is observed and reader panics propagate.
    let transfer = tokio::time::timeout(READ_STALL_GUARD, async move {
        let (mut r, mut w) = tokio::io::split(o4c_stream);

        let writer = async {
            w.write_all(&expected).await?;
            w.flush().await?;
            Ok::<_, std::io::Error>(())
        };

        let mut received = vec![0_u8; expected_total];
        let reader = async {
            let mut off = 0;
            while off < received.len() {
                let n = r.read(&mut received[off..]).await?;
                if n == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        format!("echo ended after {off}/{} bytes", received.len()),
                    ));
                }
                off += n;
                trace!("received: {n}: total:{off}");
            }
            Ok::<_, std::io::Error>(())
        };

        tokio::try_join!(writer, reader)?;

        if let Some(off) = received
            .iter()
            .zip(expected.iter())
            .position(|(got, want)| got != want)
        {
            panic!(
                "echo content mismatch at offset {off}: sent {}, got {}",
                expected[off], received[off]
            );
        }
        Ok::<_, std::io::Error>(())
    })
    .await;

    let transfer = match transfer {
        Ok(result) => result,
        Err(_) => panic!("transfer did not finish within {READ_STALL_GUARD:?}"),
    };

    let echoed = echo.await.expect("echo task panicked")?;
    assert_eq!(
        echoed, expected_total as u64,
        "echo task copied {echoed} bytes, expected {expected_total}"
    );

    transfer?;
    Ok(())
}
// Repro for the tor-socks5 cold-consensus stall: a ~3 MiB one-directional
// transfer over a REAL TCP loopback socket (not an in-memory `duplex`, which
// has no real backpressure / partial-frame boundaries). The server sends, the
// client drains with a small buffer and a 5 s idle-stall detector — mirroring
// arti pulling the directory consensus down through the obfs4 PT.
#[allow(non_snake_case)]
#[tokio::test]
async fn transfer_3M_real_tcp() -> Result<()> {
    init_subscriber();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let mut rng = rand::thread_rng();

    let o4_server = Server::new_from_random(&mut rng);
    let client_config = o4_server.client_params();

    const TOTAL: usize = 3 * 1024 * 1024;

    // Server: accept, obfs4-wrap, send TOTAL bytes in 4 KiB writes.
    tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut o4s = o4_server.wrap(&mut s).await.unwrap();
        let chunk = [7_u8; 4096];
        let mut sent = 0usize;
        while sent < TOTAL {
            let n = std::cmp::min(chunk.len(), TOTAL - sent);
            o4s.write_all(&chunk[..n])
                .await
                .unwrap_or_else(|e| panic!("server write failed at {sent}: {e}"));
            sent += n;
        }
        o4s.flush().await.unwrap();
        debug!("server: sent all {sent} bytes");
        // Hold the connection open until the client has drained everything.
        tokio::time::sleep(Duration::from_secs(30)).await;
    });

    let c = tokio::net::TcpStream::connect(addr).await?;
    let o4_client = client_config.build();
    let mut o4c = o4_client.wrap(c).await?;

    let mut buf = vec![0_u8; 16 * 1024];
    let mut received = 0usize;
    loop {
        let res = tokio::time::timeout(Duration::from_secs(5), o4c.read(&mut buf)).await;
        match res {
            Err(_) => panic!("STALL: client idle 5s after {received}/{TOTAL} bytes"),
            Ok(r) => {
                let n = r?;
                if n == 0 {
                    break;
                }
                received += n;
                if received >= TOTAL {
                    break;
                }
            }
        }
    }
    assert_eq!(received, TOTAL, "received {received} != {TOTAL}");
    Ok(())
}

// Same as `transfer_3M_real_tcp` but the server writes in 1024-byte pieces,
// each SMALLER than the per-frame `chunk_size` (~1427B). That keeps poll_write
// out of its multi-chunk `while` loop (and its backpressure early-return),
// exercising only the single trailing-frame path. If this PASSES while the
// 4096-byte variant FAILS, the desync lives in the while-loop backpressure path.
#[allow(non_snake_case)]
#[tokio::test]
async fn transfer_3M_real_tcp_small_writes() -> Result<()> {
    init_subscriber();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let mut rng = rand::thread_rng();

    let o4_server = Server::new_from_random(&mut rng);
    let client_config = o4_server.client_params();

    const TOTAL: usize = 3 * 1024 * 1024;

    tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut o4s = o4_server.wrap(&mut s).await.unwrap();
        let chunk = [7_u8; 1024];
        let mut sent = 0usize;
        while sent < TOTAL {
            let n = std::cmp::min(chunk.len(), TOTAL - sent);
            o4s.write_all(&chunk[..n])
                .await
                .unwrap_or_else(|e| panic!("server write failed at {sent}: {e}"));
            sent += n;
        }
        o4s.flush().await.unwrap();
        tokio::time::sleep(Duration::from_secs(30)).await;
    });

    let c = tokio::net::TcpStream::connect(addr).await?;
    let o4_client = client_config.build();
    let mut o4c = o4_client.wrap(c).await?;

    let mut buf = vec![0_u8; 16 * 1024];
    let mut received = 0usize;
    loop {
        let res = tokio::time::timeout(Duration::from_secs(5), o4c.read(&mut buf)).await;
        match res {
            Err(_) => panic!("STALL: client idle 5s after {received}/{TOTAL} bytes"),
            Ok(r) => {
                let n = r?;
                if n == 0 {
                    break;
                }
                received += n;
                if received >= TOTAL {
                    break;
                }
            }
        }
    }
    assert_eq!(received, TOTAL, "received {received} != {TOTAL}");
    Ok(())
}

#[tokio::test]
async fn transfer_2_x() -> Result<()> {
    init_subscriber();

    let (c, mut s) = tokio::io::duplex(1024 * 1000);
    let mut rng = rand::thread_rng();

    let o4_server = Server::new_from_random(&mut rng);
    let client_config = o4_server.client_params();

    tokio::spawn(async move {
        let o4s_stream = o4_server.wrap(&mut s).await.unwrap();
        let (mut r, mut w) = tokio::io::split(o4s_stream);
        tokio::io::copy(&mut r, &mut w).await.unwrap();
    });

    let o4_client = client_config.build();
    let o4c_stream = o4_client.wrap(c).await?;

    let (mut r, mut w) = tokio::io::split(o4c_stream);

    let base: usize = 2;
    tokio::spawn(async move {
        for i in (0..20).step_by(2) {
            let msg = vec![0_u8; base.pow(i)];
            w.write_all(&msg)
                .await
                .unwrap_or_else(|_| panic!("failed on write #{i}"));
            debug!("wrote 2^{i}");
            w.flush().await.unwrap();
        }
    });

    let mut buf = vec![0_u8; 1024 * 1024 * 100];
    let expected_total: usize = (0..20).step_by(2).map(|i| base.pow(i)).sum();
    let mut received = 0;

    let mut i = 0;
    loop {
        let res_timeout =
            tokio::time::timeout(Duration::from_millis(10000), r.read(&mut buf)).await;

        let res = res_timeout.unwrap();
        let n = res?;
        received += n;
        if n == 0 {
            debug!("read 0?");
            break;
        } else {
            debug!("({i}) read {n}B - {received}");
        }

        match received.cmp(&expected_total) {
            Ordering::Less => {}
            Ordering::Equal => break,
            Ordering::Greater => {
                panic!("received more than expected {received} > {expected_total}")
            }
        }
        i += 1;
    }

    if received != expected_total {
        panic!("incorrect amount received {received} != {expected_total}");
    }
    Ok(())
}
