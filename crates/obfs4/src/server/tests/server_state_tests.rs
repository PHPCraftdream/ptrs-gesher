use super::*;

#[tokio::test]
async fn builder_advertises_effective_state_identity_for_handshake() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let state_dir = temporary.path().join("server");

    let mut initial = ServerBuilder::<tokio::io::DuplexStream>::default();
    initial.statefile_path(state_dir.to_string_lossy().as_ref());
    initial.try_build()?;

    let mut builder = ServerBuilder::<tokio::io::DuplexStream>::default();
    builder.statefile_path(state_dir.to_string_lossy().as_ref());
    let advertised = builder.try_client_params()?;
    assert!(!advertised.is_empty());

    let replacement_dir = temporary.path().join("replacement");
    let mut replacement = ServerBuilder::<tokio::io::DuplexStream>::default();
    replacement.statefile_path(replacement_dir.to_string_lossy().as_ref());
    replacement.try_build()?;
    let replacement_state = std::fs::read(replacement_dir.join(STATE_FILENAME))?;
    std::fs::copy(
        replacement_dir.join(STATE_FILENAME),
        state_dir.join(STATE_FILENAME),
    )?;

    let server = builder.try_build()?;
    assert_eq!(builder.try_client_params()?, advertised);
    assert_eq!(
        ptrs::args::Args::parse_client_parameters(&server.client_params().as_opts()).unwrap(),
        ptrs::args::Args::parse_smethod_args(&advertised).unwrap()
    );
    assert_eq!(
        std::fs::read(state_dir.join(STATE_FILENAME))?,
        replacement_state
    );
    use ptrs::ServerBuilder as _;
    assert_eq!(
        <ServerBuilder<tokio::io::DuplexStream> as ptrs::ServerBuilder<
            tokio::io::DuplexStream,
        >>::get_client_params(&builder),
        advertised
    );
    builder.statefile_path(state_dir.to_string_lossy().as_ref());
    let reloaded_advertised = builder.try_client_params()?;
    assert_ne!(reloaded_advertised, advertised);
    let reloaded_server = builder.try_build()?;
    assert_eq!(
        ptrs::args::Args::parse_client_parameters(&reloaded_server.client_params().as_opts())
            .unwrap(),
        ptrs::args::Args::parse_smethod_args(&reloaded_advertised).unwrap()
    );
    assert_eq!(
        std::fs::read(state_dir.join(STATE_FILENAME))?,
        replacement_state
    );
    let smethod_args = ptrs::args::Args::parse_smethod_args(&advertised).unwrap();
    let mut client_builder = ClientBuilder::default();
    <ClientBuilder as ptrs::ClientBuilder<tokio::io::DuplexStream>>::options(
        &mut client_builder,
        &smethod_args,
    )?;
    let client = client_builder.build();

    let (mut client_io, mut server_io) = tokio::io::duplex(65_536);
    let (server_result, client_result) =
        tokio::join!(server.wrap(&mut server_io), client.wrap(&mut client_io));
    server_result?;
    client_result?;
    Ok(())
}

#[test]
fn unresolved_state_does_not_publish_random_identity() {
    let temporary = tempfile::tempdir().unwrap();
    let state_dir = temporary.path().join("server");
    std::fs::create_dir_all(&state_dir).unwrap();
    let state_path = state_dir.join(STATE_FILENAME);
    std::fs::write(&state_path, b"not json").unwrap();
    let original = std::fs::read(&state_path).unwrap();

    let mut builder = ServerBuilder::<TcpStream>::default();
    builder.statefile_path(state_dir.to_string_lossy().as_ref());
    assert!(builder.client_params().is_empty());
    assert!(builder.try_client_params().is_err());
    assert!(builder.try_build().is_err());
    assert!(builder.client_params().is_empty());
    assert_eq!(std::fs::read(state_path).unwrap(), original);
}

#[test]
fn effective_client_params_follow_manual_setters_after_build() {
    let mut builder = ServerBuilder::<TcpStream>::default();
    builder.try_build().unwrap();
    let before = builder.client_params();

    builder.iat_mode(IAT::Enabled);
    let after = builder.client_params();

    assert!(!before.is_empty());
    assert_ne!(before, after);
    assert!(after.contains("iat-mode=1"));
}

#[test]
fn manual_persistence_conflict_does_not_overwrite_external_state() {
    let temporary = tempfile::tempdir().unwrap();
    let state_dir = temporary.path().join("server");
    let mut initial = ServerBuilder::<TcpStream>::default();
    initial.statefile_path(state_dir.to_string_lossy().as_ref());
    initial.try_build().unwrap();

    let mut builder = ServerBuilder::<TcpStream>::default();
    builder.statefile_path(state_dir.to_string_lossy().as_ref());
    builder.iat_mode(IAT::Enabled);
    assert!(!builder.try_client_params().unwrap().is_empty());

    let replacement_dir = temporary.path().join("replacement");
    let mut replacement = ServerBuilder::<TcpStream>::default();
    replacement.statefile_path(replacement_dir.to_string_lossy().as_ref());
    replacement.try_build().unwrap();
    let replacement_state = std::fs::read(replacement_dir.join(STATE_FILENAME)).unwrap();
    std::fs::copy(
        replacement_dir.join(STATE_FILENAME),
        state_dir.join(STATE_FILENAME),
    )
    .unwrap();

    assert!(builder.try_build().is_err());
    assert_eq!(
        std::fs::read(state_dir.join(STATE_FILENAME)).unwrap(),
        replacement_state
    );
}

#[test]
fn parse_json_state_invalid_json() {
    let mut args = Args::new();
    let result =
        ServerBuilder::<TcpStream>::server_state_from_json("not json".as_bytes(), &mut args);
    assert!(result.is_err());
}

#[test]
fn json_extend_args_partial() {
    let json_str = r#"{"node-id": "aabb"}"#;
    let mut args = Args::new();
    ServerBuilder::<TcpStream>::server_state_from_json(json_str.as_bytes(), &mut args).unwrap();
    assert_eq!(args.retrieve(NODE_ID_ARG), Some("aabb".into()));
    assert!(args.retrieve(PRIVATE_KEY_ARG).is_none());
}

#[test]
fn validate_args_missing_fields() {
    let args = Args::new();
    let result = ServerBuilder::<TcpStream>::validate_args(&args);
    assert!(result.is_err());
}
