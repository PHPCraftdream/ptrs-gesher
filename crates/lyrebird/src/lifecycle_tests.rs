use super::*;
use crate::lifecycle::join_connection_tasks;

#[tokio::test(start_paused = true)]
async fn cancellation_interrupts_a_full_connection_limit() {
    use futures::FutureExt;
    let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
    let _occupied = semaphore.acquire().await.unwrap();
    let cancel = CancellationToken::new();
    let permit = connection_permit(semaphore.clone(), &cancel);
    tokio::pin!(permit);
    assert!(permit.as_mut().now_or_never().is_none());
    cancel.cancel();
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(1), permit).await;
    assert!(matches!(outcome, Ok(None)));
}

#[tokio::test(start_paused = true)]
async fn forced_shutdown_aborts_and_joins_pending_connection() {
    struct DropMarker(Arc<std::sync::atomic::AtomicBool>);

    impl Drop for DropMarker {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::Release);
        }
    }

    let ctx = RunTasks::new();
    let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let dropped_by_task = Arc::clone(&dropped);
    let permit = ctx
        .lifecycle
        .clone()
        .acquire_owned()
        .await
        .expect("test lifecycle permit");
    ctx.spawn_connection(async move {
        let _permit = permit;
        let _marker = DropMarker(dropped_by_task);
        std::future::pending::<()>().await;
    })
    .await;

    let started = tokio::time::Instant::now();
    tokio::time::timeout(std::time::Duration::from_secs(6), cancel_connections(&ctx))
        .await
        .expect("forced shutdown must abort a pending connection");

    assert!(started.elapsed() >= std::time::Duration::from_secs(5));
    assert!(dropped.load(std::sync::atomic::Ordering::Acquire));
    assert!(ctx.connections.lock().await.is_empty());
}

#[tokio::test]
async fn dropping_run_owner_aborts_active_connection() {
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        owner_aborts_active_connection(),
    )
    .await
    .expect("owner cancellation must release the connection");
}

async fn owner_aborts_active_connection() {
    use tokio::io::AsyncReadExt;

    struct DropMarker(Arc<std::sync::atomic::AtomicBool>);

    impl Drop for DropMarker {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::Release);
        }
    }

    let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let dropped_by_task = Arc::clone(&dropped);
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (state_tx, state_rx) = tokio::sync::oneshot::channel();
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind socket");
    let address = listener.local_addr().expect("socket address");
    let client_task = tokio::spawn(TcpStream::connect(address));
    let (server_socket, _) = listener.accept().await.expect("accept socket");
    drop(listener);
    let mut client_socket = client_task
        .await
        .expect("client dial task")
        .expect("client socket");
    let run = tokio::spawn(async move {
        let owner = RunOwner::new();
        let ctx = owner.tasks();
        let permit = ctx
            .lifecycle
            .clone()
            .acquire_owned()
            .await
            .expect("test lifecycle permit");
        ctx.spawn_connection(async move {
            let _permit = permit;
            let _socket = server_socket;
            let _marker = DropMarker(dropped_by_task);
            started_tx.send(()).expect("started receiver");
            std::future::pending::<()>().await;
        })
        .await;
        state_tx
            .send((ctx.lifecycle.clone(), ctx.connections.clone()))
            .expect("state receiver");
        std::future::pending::<()>().await;
    });
    started_rx.await.expect("connection task started");
    let (lifecycle, connections) = state_rx.await.expect("lifecycle state");
    let scheduler_lock = connections.lock().await;
    run.abort();
    let _ = run.await;
    drop(scheduler_lock);
    let _ = connections.lock().await.join_next().await;
    let mut bytes = Vec::new();
    client_socket
        .read_to_end(&mut bytes)
        .await
        .expect("read released socket");
    assert!(bytes.is_empty());

    assert!(dropped.load(std::sync::atomic::Ordering::Acquire));
    assert_eq!(lifecycle.available_permits(), MAX_CONCURRENT_CONNS);
    assert!(connections.lock().await.is_empty());
}

#[tokio::test]
async fn setup_error_drops_pending_stdin_future() {
    struct DropMarker(Arc<std::sync::atomic::AtomicBool>);

    impl Drop for DropMarker {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::Release);
        }
    }

    let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let marker = DropMarker(Arc::clone(&dropped));
    let stdin_wait = async move {
        let _marker = marker;
        std::future::pending::<std::io::Result<()>>().await
    };
    let setup = async { Err::<JoinSet<Result<()>>, _>(anyhow!("injected setup failure")) };

    let result = run_with_setup(RunTasks::new(), stdin_wait, setup, || {
        std::future::pending::<Shutdown>()
    })
    .await;

    assert_eq!(result.unwrap_err().to_string(), "injected setup failure");
    assert!(dropped.load(std::sync::atomic::Ordering::Acquire));
}

#[tokio::test]
async fn dropping_run_owner_during_setup_cancels_setup() {
    tokio::time::timeout(std::time::Duration::from_secs(5), owner_cancels_setup())
        .await
        .expect("owner cancellation must finish during setup");
}

async fn owner_cancels_setup() {
    let (token_tx, token_rx) = tokio::sync::oneshot::channel();
    let run = tokio::spawn(async move {
        let owner = RunOwner::new();
        let ctx = owner.tasks();
        token_tx.send(ctx.accept.clone()).expect("token receiver");
        run_with_setup(
            ctx,
            std::future::pending::<std::io::Result<()>>(),
            std::future::pending::<Result<JoinSet<Result<()>>>>(),
            std::future::pending::<Shutdown>,
        )
        .await
    });

    let accept = token_rx.await.expect("accept token");
    run.abort();
    assert!(run.await.is_err(), "aborted run should not return normally");
    assert!(accept.is_cancelled());
}

#[tokio::test]
async fn reaping_join_error_removes_abort_handle_by_task_id() {
    let ctx = RunTasks::new();
    ctx.spawn_connection(std::future::pending::<()>()).await;
    assert_eq!(ctx.aborts.lock().unwrap().len(), 1);

    ctx.connections.lock().await.abort_all();
    join_connection_tasks(&ctx).await;

    assert!(ctx.aborts.lock().unwrap().is_empty());
    assert!(ctx.connections.lock().await.is_empty());
}

#[tokio::test]
async fn cancellation_race_after_scheduler_lock_releases_registered_task() {
    let owner = RunOwner::new();
    let ctx = owner.tasks();
    let scheduler_lock = ctx.connections.lock().await;
    let admission = tokio::spawn({
        let ctx = ctx.clone();
        async move { ctx.spawn_connection(async {}).await }
    });
    tokio::task::yield_now().await;

    drop(owner);
    drop(scheduler_lock);
    admission.await.unwrap();
    join_connection_tasks(&ctx).await;

    assert!(ctx.aborts.lock().unwrap().is_empty());
}
