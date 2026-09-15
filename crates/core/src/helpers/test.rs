use super::*;

use serial_test::serial;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[test]
#[serial]
fn is_client_from_env() -> Result<(), Error> {
    env::remove_var(constants::CLIENT_TRANSPORTS);
    env::remove_var(constants::SERVER_TRANSPORTS);
    assert!(is_client().is_err());

    env::set_var(constants::CLIENT_TRANSPORTS, "trebuchet");
    env::remove_var(constants::SERVER_TRANSPORTS);
    let c = is_client();
    assert!(c.is_ok());
    assert!(c.unwrap());

    env::remove_var(constants::CLIENT_TRANSPORTS);
    env::set_var(constants::SERVER_TRANSPORTS, "trebuchet1");
    let c = is_client();
    assert!(c.is_ok());
    assert!(!c.unwrap());

    env::set_var(constants::CLIENT_TRANSPORTS, "trebuchet2");
    env::set_var(constants::SERVER_TRANSPORTS, "trebuchet2");
    assert!(is_client().is_err());

    Ok(())
}

#[test]
#[serial]
fn statedir() -> Result<(), Error> {
    // TOR_PT_STATE_LOCATION not set.
    env::remove_var(constants::STATE_LOCATION);
    if make_state_dir().is_ok() {
        panic!("empty environment unexpectedly succeeded");
    }

    // Setup the scratch directory.
    let temp_dir = tempfile::tempdir()?;
    // temp_dir, err := ioutil.TempDir("", "testmake_state_dir")
    // if err != nil {
    //     t.Fatalf("ioutil.TempDir failed: %s", err)
    // }
    // defer os.RemoveAll(temp_dir)

    let good = vec![
        // Already existing directory.
        temp_dir.path().to_path_buf(),
        // Nonexistent directory, parent exists.
        temp_dir.path().join("parentExists"),
        // Nonexistent directory, parent doesn't exist.
        temp_dir.path().join("missingParent").join("parentMissing"),
    ];
    for trial in good {
        env::set_var("TOR_PT_STATE_LOCATION", trial.to_str().unwrap());
        let dir = make_state_dir()?;
        if dir != trial.to_str().unwrap() {
            panic!("make_state_dir returned an unexpected path {dir} (expecting {trial:?})");
        }
    }

    // Name already exists, but is an ordinary file.
    let temp_file = temp_dir.path().join("file");
    let _ = std::fs::File::create(&temp_file)?;

    env::set_var("TOR_PT_STATE_LOCATION", &temp_file);
    assert!(
        make_state_dir().is_err(),
        "make_state_dir with a file unexpectedly succeeded"
    );

    // Directory name that cannot be created. (Subdir of a file)
    env::set_var("TOR_PT_STATE_LOCATION", temp_file.join("subDir"));
    assert!(
        make_state_dir().is_err(),
        "make_state_dir with a subdirectory of a file unexpectedly succeeded"
    );

    Ok(())
}

#[test]
#[serial]
fn server_bindaddrs() -> Result<(), Error> {
    // // test with env vars unset
    // assert_eq!(Bindaddr::get_server_bindaddrs().unwrap_err(), env::VarError);
    assert!(Bindaddr::get_server_bindaddrs().is_err());

    let bad = vec![
        // bad TOR_PT_SERVER_BINDADDR
        ("alpha", "alpha", ""),
        ("alpha-1.2.3.4", "alpha", ""),
        // missing TOR_PT_SERVER_TRANSPORTS
        ("alpha-1.2.3.4:1111", "", "alpha:key=value"),
        // bad TOR_PT_SERVER_TRANSPORT_OPTIONS
        ("alpha-1.2.3.4:1111", "alpha", "key=value"),
        // no escaping is defined for TOR_PT_SERVER_TRANSPORTS or
        // TOR_PT_SERVER_BINDADDR.
        (r"alpha\,beta-1.2.3.4:1111", r"alpha\,beta", ""),
        // duplicates in TOR_PT_SERVER_BINDADDR
        // https://bugs.torproject.org/21261
        (r"alpha-0.0.0.0:1234,alpha-[::]:1234", r"alpha", ""),
        (r"alpha-0.0.0.0:1234,alpha-0.0.0.0:1234", r"alpha", ""),
    ];

    for trial in bad {
        env::set_var(constants::SERVER_BINDADDR, trial.0);
        env::set_var(constants::SERVER_TRANSPORTS, trial.1);
        env::set_var(constants::SERVER_TRANSPORT_OPTIONS, trial.2);
        assert!(
            Bindaddr::get_server_bindaddrs().is_err(),
            "{:?} unexpectedly succeeded",
            trial
        );
    }

    let good = vec![
        (
            "alpha-1.2.3.4:1111,beta-[1:2::3:4]:2222",
            "alpha,beta,gamma",
            "alpha:k1=v1;beta:k2=v2;gamma:k3=v3",
            vec![
                Bindaddr::new(
                    "alpha",
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 1111),
                    args! {"k1"=>["v1"]},
                ),
                Bindaddr::new(
                    "beta",
                    SocketAddr::new(IpAddr::V6(Ipv6Addr::new(1, 2, 0, 0, 0, 0, 3, 4)), 2222),
                    args! {"k2"=>["v2"]},
                ),
            ],
        ),
        ("alpha-1.2.3.4:1111", "xxx", "", vec![]),
        (
            "alpha-1.2.3.4:1111",
            "alpha,beta,gamma",
            "",
            vec![Bindaddr::new(
                "alpha",
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 1111),
                Args::default(),
            )],
        ),
        (
            "trebuchet-127.0.0.1:1984,ballista-127.0.0.1:4891",
            "trebuchet,ballista",
            "trebuchet:secret=nou;trebuchet:cache=/tmp/cache;ballista:secret=yes",
            vec![
                Bindaddr::new(
                    "trebuchet",
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1984),
                    args! {"secret"=>["nou"], "cache"=>["/tmp/cache"]},
                ),
                Bindaddr::new(
                    "ballista",
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 4891),
                    args!("secret"=>["yes"]),
                ),
            ],
        ),
        // In the past, "*" meant to return all known transport names.
        // But now it has no special meaning.
        // https://bugs.torproject.org/15612
        ("alpha-1.2.3.4:1111,beta-[1:2::3:4]:2222", "*", "", vec![]),
    ];

    for trial in good {
        env::set_var(constants::SERVER_BINDADDR, trial.0);
        env::set_var(constants::SERVER_TRANSPORTS, trial.1);
        env::set_var(constants::SERVER_TRANSPORT_OPTIONS, trial.2);

        let out = Bindaddr::get_server_bindaddrs();
        assert!(out.is_ok(), "{:?} unexpectedly failed: {out:?}", trial);

        assert_eq!(out.unwrap(), trial.3);
    }
    Ok(())
}

#[test]
#[serial]
fn validate_url() -> Result<(), Error> {
    env::remove_var(constants::PROXY);
    let url = get_proxy_url();
    assert!(url.is_ok());
    assert!(url.unwrap().is_none());

    let bad_url = vec![
        "asdals;kdmma",
        "http/example.com",
        "127.0.0.1:8080",
        "socks5://admin:admin@:9000", // No host
    ];

    let bad = vec![
        "socks5://admin:admin@1.2.3.4:",
        "ftp://127.0.0.1:8000",              // invalid protocol
        "socks5://aaa:bbb@1.2.3.4:80/a/b/c", // includes path
        "socks5://aaa:bbb@1.2.3.4:80/?labels=E-easy&state=open", // includes query
        "socks5://aaa:bbb@1.2.3.4:80#row=4", // includes fragment
        "socks5://myhost",                   // no username / password
        "socks5://myproxy:8080",             // uses non-IP host alias
        "socks5://aaa:bbb@myhost.com:8888",  // uses domain name
        "socks5://aaa:bbb@myhost",           // uses non-IP host alias
        "socks4a://:admin@1.2.3.4:8080",     // no username, but password defined
        "http://admin:admin@example.com",
        "socks5://1.2.3.4", // no port
        "http://1.2.3.4",   // omitted default port is still invalid
        "socks5://[1:2::3:4]",
        "socks5://admin:admin@1.2.3.4",
        "socks4a://1.2.3.4",
        "socks4a://[1:2::3:4]",
        "socks5://admin:admin@[1:2::3:4]",
        "socks4a://admin:admin@1.2.3.4:8080", // socks4 with password
        "socks4a://:admin@1.2.3.4:8080",      // socks4a with password
        "socks5://admin@[1:2::3:4]:9000",     // socks5 with username, but no password
        "socks5://:admin@[1:2::3:4]:9000",    // socks5 wuth password, but no username
    ];

    let good = vec![
        "socks5://127.0.0.1:8080",
        "socks5://1.2.3.4:8080",
        "socks5://[1:2::3:4]:8080",
        "socks5://admin:admin@1.2.3.4:8080",
        "socks5://admin:admin@1.2.3.4:8080",
        "socks5://admin:admin@[1:2::3:4]:9000",
        "socks4a://1.2.3.4:8080",
        "socks4a://[1:2::3:4]:8080",
        "socks4a://admin@1.2.3.4:8080",
        "http://1.2.3.4:8080",
        "http://[1:2::3:4]:8080",
        "http://admin@1.2.3.4:8080",
        "http://admin:admin@1.2.3.4:8080",
    ];

    for trial in bad_url {
        let url = Url::parse(trial);
        assert!(
            url.is_err(),
            "\"{trial}\" unexpectedly succeeded in parsing: {url:?}"
        );
    }

    for trial in bad {
        let url = Url::parse(trial).unwrap();
        assert!(
            validate_proxy_url(&url).is_err(),
            "\"{trial}\" unexpectedly succeeded validation: {url:?}"
        );
    }

    for trial in good {
        env::set_var(constants::PROXY, trial);

        let res = get_proxy_url();
        assert!(
            res.is_ok(),
            "\"{trial}\" unexpectedly failed to validate: {res:?}"
        );
    }

    for trial in [
        "http://127.0.0.1:80",
        "http://user:secret@127.0.0.1:80",
        "http://[::1]:80",
    ] {
        env::set_var(constants::PROXY, trial);
        assert!(
            get_proxy_url()?.is_some(),
            "explicit default port should be accepted: {trial}"
        );
    }

    for trial in [
        "http://127.0.0.1:",
        "http://user:secret@127.0.0.1:",
        "http://[::1]:",
        "http://127.0.0.1\\path:80",
        "http://127.0.0.1 path:80",
    ] {
        env::set_var(constants::PROXY, trial);
        assert!(
            get_proxy_url().is_err(),
            "empty proxy port should be rejected: {trial}"
        );
    }

    Ok(())
}

#[test]
#[serial]
fn client_transports() -> Result<(), Error> {
    let tests: Vec<(&str, Vec<&str>)> = vec![
        ("alpha", vec!["alpha"]),
        ("alpha,beta", vec!["alpha", "beta"]),
        ("alpha,beta,gamma", vec!["alpha", "beta", "gamma"]),
        // In the past, "*" meant to return all known transport names.
        // But now it has no special meaning.
        // https://bugs.torproject.org/15612
        ("*", vec!["*"]),
        ("alpha,*,gamma", vec!["alpha", "*", "gamma"]),
        // No escaping is defined for TOR_PT_CLIENT_TRANSPORTS.
        ("alpha\\,beta", vec!["alpha\\", "beta"]),
    ];

    for trial in tests {
        env::set_var(constants::CLIENT_TRANSPORTS, trial.0);
        let result = get_client_transports()?;
        assert_eq!(result, trial.1);
    }

    Ok(())
}

#[test]
#[serial]
fn resolve() -> Result<(), Error> {
    let bad = vec![
        "",
        "1.2.3.4",
        "1.2.3.4:",
        "9999",
        ":9999",
        "[1:2::3:4]",
        "[1:2::3:4]:",
        "[1::2::3:4]",
        "1:2::3:4::9999",
        "1:2::3:4:9999", // moved from good cases since this is not proper format
        "1:2:3:4::9999",
        "localhost:9999",
        "[localhost]:9999",
        "1.2.3.4:http",
        "1.2.3.4:0x50",
        "1.2.3.4:-65456",
        "1.2.3.4:65536",
        "1.2.3.4:80\x00",
        "1.2.3.4:80 ",
        " 1.2.3.4:80",
        "1.2.3.4 : 80",
        "www.google.com", // not a socket address (domain)
        "google.com:443", // not a socket address (domain)
        "0.0.0.0:9000",   // no address specified
        "[0::0000]:9000", // no address specified
        "127.0.0.1:0",    // no port specified
        "[1234::cdef]:0", // no port specified
        "127.0.0",        // not an address
    ];
    let good: Vec<(&str, SocketAddr)> = vec![
        (
            "1.2.3.4:9999",
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 9999),
        ),
        (
            "[1:2::3:4]:9999",
            SocketAddr::new(IpAddr::V6(Ipv6Addr::new(1, 2, 0, 0, 0, 0, 3, 4)), 9999),
        ),
        // // this is not a properly formatted ipv6 address
        // ("1:2::3:4:9999",SocketAddr::new(IpAddr::V6(Ipv6Addr::new(1, 2, 0, 0, 0, 0, 3, 4)), 9999)),
    ];

    for trial in good {
        let res = resolve_addr(trial.0).unwrap();
        assert_eq!(res, trial.1);
    }

    for trial in bad {
        assert!(resolve_addr(trial).is_err());
    }
    Ok(())
}

#[test]
#[serial]
fn managed_ver() -> Result<(), Error> {
    let good = vec!["1", "1,1", "1,2", "2,1", "3,2,1", "3,1,2"];

    for trial in good {
        env::set_var(constants::MANAGED_VER, trial);
        assert_eq!(
            get_managed_transport_ver()?,
            constants::CURRENT_TRANSPORT_VER
        );
    }

    env::set_var(constants::MANAGED_VER, "");
    assert!(get_managed_transport_ver().is_err());

    env::set_var(constants::MANAGED_VER, "3,2");
    assert!(get_managed_transport_ver().is_err());

    Ok(())
}

// -- pt_should_exit_on_stdin_close --

#[test]
#[serial]
fn exit_on_stdin_close_returns_true_when_set() {
    env::set_var(constants::EXIT_ON_STDIN_CLOSE, "1");
    assert!(pt_should_exit_on_stdin_close());
}

#[test]
#[serial]
fn exit_on_stdin_close_returns_false_when_not_one() {
    env::set_var(constants::EXIT_ON_STDIN_CLOSE, "0");
    assert!(!pt_should_exit_on_stdin_close());

    env::set_var(constants::EXIT_ON_STDIN_CLOSE, "yes");
    assert!(!pt_should_exit_on_stdin_close());
}

#[test]
#[serial]
fn exit_on_stdin_close_returns_false_when_unset() {
    env::remove_var(constants::EXIT_ON_STDIN_CLOSE);
    assert!(!pt_should_exit_on_stdin_close());
}

// -- wait_reader_close --
//
// wait_stdin_close is just wait_reader_close wired to process stdin,
// so we exercise the reader-generic version with a stand-in reader
// (Cursor / failing reader). Each test is wrapped in a timeout so a
// regression that fails to observe EOF surfaces as a test failure
// rather than hanging the suite.

#[tokio::test]
#[serial]
async fn wait_reader_close_returns_on_immediate_eof() {
    use std::io::Cursor;
    use std::time::Duration;
    // An empty reader is already at EOF; the function must return
    // promptly (not block waiting for bytes that will never arrive).
    let reader = Cursor::new(Vec::<u8>::new());
    tokio::time::timeout(Duration::from_secs(2), wait_reader_close(reader))
        .await
        .expect("wait_reader_close must return on immediate EOF, not hang");
}

#[tokio::test]
#[serial]
async fn wait_reader_close_drains_bytes_then_returns_on_eof() {
    use std::io::Cursor;
    use std::time::Duration;
    // A non-empty reader: the read loop must consume every byte
    // before observing EOF and returning. (A regression that returns
    // after the first 0-byte read without consuming would also pass
    // the immediate-EOF test, so this case is necessary on its own.)
    let reader = Cursor::new(b"some fake stdin bytes".to_vec());
    tokio::time::timeout(Duration::from_secs(2), wait_reader_close(reader))
        .await
        .expect("wait_reader_close must drain the reader and return on EOF");
}

#[tokio::test]
#[serial]
async fn wait_reader_close_returns_on_reader_error() {
    use std::io::{self, Read};
    use std::time::Duration;
    // A reader that always errors: the loop must treat this the same
    // as EOF and return, rather than spinning on the failing read.
    struct AlwaysErr;
    impl Read for AlwaysErr {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("boom"))
        }
    }
    tokio::time::timeout(Duration::from_secs(2), wait_reader_close(AlwaysErr))
        .await
        .expect("wait_reader_close must return when the reader errors, not hang");
}
