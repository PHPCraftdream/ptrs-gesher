use super::*;

fn node_keys(byte: u8) -> [u8; KEY_LENGTH * 2] {
    let secret = crate::common::x25519_elligator2::StaticSecret::from([byte; KEY_LENGTH]);
    let public = crate::common::x25519_elligator2::PublicKey::from(&secret);
    let mut keys = [0_u8; KEY_LENGTH * 2];
    keys[..KEY_LENGTH].copy_from_slice(&secret.to_bytes());
    keys[KEY_LENGTH..].copy_from_slice(public.as_bytes());
    keys
}

fn state_server(directory: &std::path::Path, node_id: [u8; NODE_ID_LENGTH]) -> Result<Server> {
    std::fs::create_dir_all(directory)?;
    let server = Server::new([0x11; KEY_LENGTH], node_id);
    server.write_statefile_to(directory)?;
    Ok(server)
}

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

#[tokio::test]
async fn keypair_override_preserves_state_node_id_and_handshake() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let state_dir = temporary.path().join("server");
    let state_node_id = [0xA1; NODE_ID_LENGTH];
    state_server(&state_dir, state_node_id)?;

    let mut builder = ServerBuilder::<tokio::io::DuplexStream>::default();
    builder.statefile_path(state_dir.to_string_lossy().as_ref());
    builder.try_node_keys(node_keys(0x33))?;
    let advertised = builder.try_client_params()?;
    let server = builder.try_build()?;

    assert_eq!(server.0.identity_keys.pk.id.as_bytes(), &state_node_id);
    assert_eq!(server.0.identity_keys.sk.to_bytes(), [0x33; KEY_LENGTH]);
    let persisted: serde_json::Value =
        serde_json::from_slice(&std::fs::read(state_dir.join(STATE_FILENAME))?)
            .expect("persisted server state is valid JSON");
    let expected_node_id = hex::encode(state_node_id);
    let expected_private_key = hex::encode([0x33; KEY_LENGTH]);
    assert_eq!(
        persisted["node-id"].as_str(),
        Some(expected_node_id.as_str())
    );
    assert_eq!(
        persisted["private-key"].as_str(),
        Some(expected_private_key.as_str())
    );
    assert_eq!(builder.try_client_params()?, advertised);
    assert_eq!(
        ptrs::args::Args::parse_client_parameters(&server.client_params().as_opts()).unwrap(),
        ptrs::args::Args::parse_smethod_args(&advertised).unwrap()
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
fn keypair_and_node_id_setters_are_independent_in_both_orders() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let state_node_id = [0xA2; NODE_ID_LENGTH];
    let key_override = node_keys(0x44);

    for key_first in [true, false] {
        let state_dir = temporary
            .path()
            .join(if key_first { "keys-first" } else { "id-first" });
        state_server(&state_dir, state_node_id)?;
        let mut builder = ServerBuilder::<tokio::net::TcpStream>::default();
        if key_first {
            builder.try_node_keys(key_override)?;
            builder.statefile_path(state_dir.to_string_lossy().as_ref());
            builder.node_id([0xC3; NODE_ID_LENGTH]);
        } else {
            builder.node_id([0xC3; NODE_ID_LENGTH]);
            builder.try_node_keys(key_override)?;
            builder.statefile_path(state_dir.to_string_lossy().as_ref());
        }
        let server = builder.try_build()?;
        assert_eq!(
            server.0.identity_keys.pk.id.as_bytes(),
            &[0xC3; NODE_ID_LENGTH]
        );
        assert_eq!(server.0.identity_keys.sk.to_bytes(), [0x44; KEY_LENGTH]);
    }
    Ok(())
}

#[test]
fn try_statefile_reload_then_keypair_override_keeps_loaded_node_id() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let state_file = temporary.path().join("state.json");
    let state_node_id = [0xB5; NODE_ID_LENGTH];
    let source = Server::new([0x22; KEY_LENGTH], state_node_id);
    source.write_statefile_to(&state_file)?;
    let original = std::fs::read(&state_file)?;

    let mut builder = ServerBuilder::<tokio::net::TcpStream>::default();
    builder.try_statefile_path(state_file.to_string_lossy().as_ref())?;
    builder.try_node_keys(node_keys(0x55))?;
    let server = builder.try_build()?;

    assert_eq!(server.0.identity_keys.pk.id.as_bytes(), &state_node_id);
    assert_eq!(server.0.identity_keys.sk.to_bytes(), [0x55; KEY_LENGTH]);
    assert_eq!(std::fs::read(state_file)?, original);
    Ok(())
}

#[test]
fn options_keeps_state_node_id_without_explicit_node_id_arg() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let state_dir = temporary.path().join("server");
    let state_node_id = [0xD6; NODE_ID_LENGTH];
    state_server(&state_dir, state_node_id)?;
    let key_override = node_keys(0x66);

    let mut args = Args::new();
    args.add(PRIVATE_KEY_ARG, &hex::encode(&key_override[..KEY_LENGTH]));
    args.add(PUBLIC_KEY_ARG, &hex::encode(&key_override[KEY_LENGTH..]));
    args.add(SEED_ARG, "0a0b0c0d0e0f0a0b0c0d0e0f0a0b0c0d0e0f0a0b0c0d0e0f");
    args.add(IAT_ARG, "1");

    let mut builder = ServerBuilder::<tokio::net::TcpStream>::default();
    builder.statefile_path(state_dir.to_string_lossy().as_ref());
    <ServerBuilder<tokio::net::TcpStream> as ptrs::ServerBuilder<tokio::net::TcpStream>>::options(
        &mut builder,
        &args,
    )?;
    let server = builder.try_build()?;

    assert_eq!(server.0.identity_keys.pk.id.as_bytes(), &state_node_id);
    assert_eq!(server.0.identity_keys.sk.to_bytes(), [0x66; KEY_LENGTH]);

    let explicit_node_id = [0xE7; NODE_ID_LENGTH];
    let mut explicit_args = args.clone();
    explicit_args.add(NODE_ID_ARG, &hex::encode(explicit_node_id));
    let mut explicit_builder = ServerBuilder::<tokio::net::TcpStream>::default();
    explicit_builder.statefile_path(state_dir.to_string_lossy().as_ref());
    <ServerBuilder<tokio::net::TcpStream> as ptrs::ServerBuilder<tokio::net::TcpStream>>::options(
        &mut explicit_builder,
        &explicit_args,
    )?;
    let explicit_server = explicit_builder.try_build()?;
    assert_eq!(
        explicit_server.0.identity_keys.pk.id.as_bytes(),
        &explicit_node_id
    );
    Ok(())
}

#[test]
fn server_builder_timeout_modes() {
    let mut sb = ServerBuilder::<TcpStream>::default();

    sb.with_handshake_timeout(Duration::from_secs(10));
    assert!(matches!(sb.handshake_timeout, MaybeTimeout::Length(_)));

    sb.fail_fast();
    assert!(matches!(sb.handshake_timeout, MaybeTimeout::Unset));
}
