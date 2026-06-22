use crate::{test_utils::init_subscriber, Result, Server};

use ptrs::{debug, trace};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use std::cmp::Ordering;
use std::time::Duration;

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

#[allow(non_snake_case)]
#[tokio::test]
async fn transfer_10k_x1() -> Result<()> {
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

    tokio::spawn(async move {
        let msg = [0_u8; 10240];
        w.write_all(&msg)
            .await
            .unwrap_or_else(|e| panic!("failed on write {e}"));
        w.flush().await.unwrap();
    });

    let expected_total = 10240;
    let mut buf = vec![0_u8; 1024 * 11];
    let mut received: usize = 0;
    for i in 0..8 {
        debug!("client read: {i}");
        tokio::select! {
            res = r.read(&mut buf) => {
                let n = res?;
                received += n;
                trace!("received: {n}: total:{received}");
            }
            _ = tokio::time::sleep(std::time::Duration::from_millis(1000)) => {
                panic!("client failed to read after {i} iterations: timeout");
            }
        }
    }

    if received != expected_total {
        panic!("incorrect amount received {received} != {expected_total}");
    }
    Ok(())
}

#[allow(non_snake_case)]
#[tokio::test]
async fn transfer_10k_x3() -> Result<()> {
    init_subscriber();

    let (c, mut s) = tokio::io::duplex(1024 * 1000);

    let o4_server = Server::getrandom();
    let client_config = o4_server.client_params();

    tokio::spawn(async move {
        let o4s_stream = o4_server.wrap(&mut s).await.unwrap();
        let (mut r, mut w) = tokio::io::split(o4s_stream);
        tokio::io::copy(&mut r, &mut w).await.unwrap();
    });

    let o4_client = client_config.build();
    let o4c_stream = o4_client.wrap(c).await?;

    let (mut r, mut w) = tokio::io::split(o4c_stream);

    tokio::spawn(async move {
        for _ in 0..3 {
            let msg = [0_u8; 10240];
            w.write_all(&msg)
                .await
                .unwrap_or_else(|e| panic!("failed on write {e}"));
            w.flush().await.unwrap();
        }
    });

    let expected_total = 10240 * 3;
    let mut buf = vec![0_u8; 1024 * 32];
    let mut received: usize = 0;
    for i in 0..24 {
        // debug!("client read: {i}");
        tokio::select! {
            res = r.read(&mut buf) => {
                let n = res?;
                received += n;
                trace!("received: {n}: total:{received}");
            }
            _ = tokio::time::sleep(std::time::Duration::from_millis(1000)) => {
                panic!("client failed to read after {i} iterations: timeout");
            }
        }
    }

    if received != expected_total {
        panic!("incorrect amount received {received} != {expected_total}");
    }
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

    tokio::spawn(async move {
        let o4s_stream = o4_server.wrap(&mut s).await.unwrap();
        let (mut r, mut w) = tokio::io::split(o4s_stream);
        tokio::io::copy(&mut r, &mut w).await.unwrap();
    });

    let o4_client = client_config.build();
    let o4c_stream = o4_client.wrap(c).await?;

    let (mut r, mut w) = tokio::io::split(o4c_stream);

    tokio::spawn(async move {
        let msg = [0_u8; 1024];
        for i in 0..1024 {
            w.write_all(&msg)
                .await
                .unwrap_or_else(|e| panic!("failed on write #{i}: {e}"));
            w.flush().await.unwrap();
        }
    });

    let expected_total = 1024 * 1024;
    let mut buf = vec![0_u8; 1024 * 1024];
    let mut received: usize = 0;
    for i in 0..1024 {
        // debug!("client read: {i}");
        tokio::select! {
            res = r.read(&mut buf) => {
                received += res?;
            }
            _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => {
                panic!("client failed to read after {i} iterations: timeout");
            }
        }
    }

    if received != expected_total {
        panic!("incorrect amount received {received} != {expected_total}");
    }
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

    tokio::spawn(async move {
        let o4s_stream = o4_server.wrap(&mut s).await.unwrap();
        let (mut r, mut w) = tokio::io::split(o4s_stream);
        tokio::io::copy(&mut r, &mut w).await.unwrap();
    });

    let o4_client = client_config.build();
    let o4c_stream = o4_client.wrap(c).await?;

    let (mut r, mut w) = tokio::io::split(o4c_stream);

    tokio::spawn(async move {
        let expected_total = 1024 * 512;
        let mut buf = vec![0_u8; 1024 * 513];
        let mut received: usize = 0;
        let mut i = 0;
        while received < expected_total {
            debug!("client read: {i} / {received}");
            tokio::select! {
                res = r.read(&mut buf) => {
                    received += res.unwrap();
                }
                _ = tokio::time::sleep(std::time::Duration::from_millis(2000)) => {
                    panic!("client failed to read after {i} iterations: timeout");
                }
            }
            i += 1;
        }

        assert_eq!(
            received, expected_total,
            "incorrect amount received {received} != {expected_total}"
        );
    });

    let msg = [0_u8; 1024 * 512];
    w.write_all(&msg)
        .await
        .unwrap_or_else(|_| panic!("failed on write"));
    w.flush().await?;

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
