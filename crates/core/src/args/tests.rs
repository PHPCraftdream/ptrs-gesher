use super::*;
use crate::warn;
use std::borrow::Cow;

#[test]
fn test_get_args() {
    let args = Args(hashmap!(
        String::from("a") => vec![],
        String::from("b") => vec![String::from("value")],
        String::from("c") => vec![String::from("v1"), String::from("v2"), String::from("v3")]
    ));

    let empty = Args::new();

    if let Some(v) = empty.get("a") {
        panic!("unexpected result from `get` on empty Args: {:?}", v);
    }

    match args.get("a") {
        Some(v) => assert!(v.is_empty()),
        None => panic!("expected empty set"),
    }

    match args.get("b") {
        Some(v) => assert_eq!(
            v[0], "value",
            "Get({}) → {:?} (expected {})",
            "b", v, "value"
        ),
        None => panic!("Unexpected Get failure for \"{}\"", "b"),
    }

    match args.get("c") {
        Some(v) => assert_eq!(v[0], "v1", "Get({}) → {:?} (expected {})", "c", v, "v1"),
        None => panic!("Unexpected Get failure for \"{}\"", "c"),
    }

    if let Some(v) = args.get("d") {
        panic!("unexpected get success for \"{}\" → {:?}", "d", v);
    }
}

#[test]
fn test_add_args() {
    let mut args = Args::new();
    let mut expected = Args::new();
    assert_eq!(args, expected, "{:?} != {:?}", args, expected);

    args.add("k1", "v1");
    expected = Args(hashmap!(
        String::from("k1")=>vec![String::from("v1")]
    ));
    assert_eq!(args, expected, "{:?} != {:?}", args, expected);

    args.add("k2", "v2");
    expected = Args(hashmap!(
        String::from("k1")=>vec![String::from("v1")],
        String::from("k2") => vec![String::from("v2")]
    ));
    assert_eq!(args, expected, "{:?} != {:?}", args, expected);

    args.add("k1", "v3");
    expected = Args(hashmap!(
        String::from("k1") => vec![String::from("v1"), String::from("v3")],
        String::from("k2") => vec![String::from("v2")]
    ));
    assert_eq!(args, expected, "{:?} != {:?}", args, expected);
}

#[test]
fn test_parse_client_parameters() {
    let bad_cases = vec![
        ("key", "parsing client params found no equals sign in key"),
        ("key\\", "nothing following final escape in \"key\\\""),
        (
            "=value",
            "parsing client params encountered empty key in =value",
        ),
        (
            "==value",
            "parsing client params encountered empty key in ==value",
        ),
        (
            "==key=value",
            "parsing client params encountered empty key in ==key=value",
        ),
        (
            "key=value\\",
            "nothing following final escape in \"value\\\"",
        ),
        (
            "a=b;key=value\\",
            "nothing following final escape in \"value\\\"",
        ),
        ("a;b=c", "parsing client params found no equals sign in a"),
        (";", "parsing client params found no equals sign in "),
        (
            "key=value;",
            "parsing client params found no equals sign in ",
        ),
        (
            ";key=value",
            "parsing client params found no equals sign in ",
        ),
        (
            "key\\=value",
            "parsing client params found no equals sign in key\\=value",
        ),
    ];
    let good_cases = vec![
        ("", HashMap::new()),
        ("key=", hashmap!("key" => vec![""])),
        ("key==", hashmap!("key" => vec!["="])),
        ("key=value", hashmap!("key" => vec!["value"])),
        ("a=b=c", hashmap!("a" => vec!["b=c"])),
        ("a=bc==", hashmap!("a" => vec!["bc=="])),
        ("a\\=b=c", hashmap!("a=b" => vec!["c"])),
        ("key=a\nb", hashmap!("key" => vec!["a\nb"])),
        ("key=value\\;", hashmap!("key" => vec!["value;"])),
        ("key=\"value\"", hashmap!("key" => vec!["\"value\""])),
        ("\"key=value\"", hashmap!("\"key" => vec!["value\""])),
        (
            "key=\"\"value\"\"",
            hashmap!("key" => vec!["\"\"value\"\""]),
        ),
        (
            "key=value;key=value",
            hashmap!("key" => vec!["value", "value"]),
        ),
        (
            "key=value1;key=value2",
            hashmap!("key" => vec!["value1", "value2"]),
        ),
        (
            "key1=value1;key2=value2;key1=value3",
            hashmap!("key1" => vec!["value1", "value3"], "key2" => vec!["value2"]),
        ),
        (
            "\\;=\\;;\\\\=\\;",
            hashmap!(";" => vec![";"], "\\" => vec![";"]),
        ),
        (
            "shared-secret=rahasia;secrets-file=/tmp/blob",
            hashmap!("shared-secret" => vec!["rahasia"], "secrets-file" => vec!["/tmp/blob"]),
        ),
        (
            "rocks=20;height=5.6",
            hashmap!("rocks" => vec!["20"], "height" => vec!["5.6"]),
        ),
    ];

    for input in bad_cases {
        match Args::parse_client_parameters(input.0) {
            Ok(_) => panic!("{} unexpectedly succeeded: expected {}", input.0, input.1),
            Err(Error::ParseError(e)) => {
                assert_eq!(e, input.1)
            }
            Err(e) => panic!("received unknown error: {e}"),
        }
    }

    for (input, exected_map) in good_cases.iter() {
        // Convert all &str to String to keep tests readable
        let expected = Args(
            exected_map
                .iter()
                .map(|(k, vs)| (k.to_string(), vs.iter().map(|v| v.to_string()).collect()))
                .collect(),
        );

        match Args::parse_client_parameters(input) {
            Ok(args) => assert_eq!(
                args, expected,
                "{} → {:?} (expected {:?})",
                input, args, expected
            ),
            Err(err) => panic!("{} unexpectedly returned an error: {}", input, err),
        }
    }
}

#[test]
fn parse_good_server_transport_options() {
    let good_cases = [
        ("", hashmap! {}),
        (
            "t:k=v",
            hashmap! {
                "t" => hashmap!{"k" => vec!["v"]}
            },
        ),
        (
            "t:k=v=v",
            hashmap! {
                "t" => hashmap!{"k" => vec!["v=v"]},
            },
        ),
        (
            "t:k=vv==",
            hashmap! {
                "t" => hashmap!{"k" => vec!["vv=="]},
            },
        ),
        (
            "t1:k=v1;t2:k=v2;t1:k=v3",
            hashmap! {
                "t1" => hashmap!{"k" => vec!["v1", "v3"]},
                "t2" => hashmap!{"k" => vec!["v2"]},
            },
        ),
        (
            "t\\:1:k=v;t\\=2:k=v;t\\;3:k=v;t\\\\4:k=v",
            hashmap! {
                "t:1" =>  hashmap!{"k" => vec!["v"]},
                "t=2" =>  hashmap!{"k" => vec!["v"]},
                "t;3" =>  hashmap!{"k" => vec!["v"]},
                "t\\4" => hashmap!{"k" => vec!["v"]},
            },
        ),
        (
            "t:k\\:1=v;t:k\\=2=v;t:k\\;3=v;t:k\\\\4=v",
            hashmap! {
                "t" => hashmap!{
                    "k:1" =>  vec!["v"],
                    "k=2" =>  vec!["v"],
                    "k;3" =>  vec!["v"],
                    "k\\4" => vec!["v"],
                },
            },
        ),
        (
            "t:k=v\\:1;t:k=v\\=2;t:k=v\\;3;t:k=v\\\\4",
            hashmap! {
                "t" => hashmap!{"k" => vec!["v:1", "v=2", "v;3", "v\\4"]},
            },
        ),
        (
            "trebuchet:secret=nou;trebuchet:cache=/tmp/cache;ballista:secret=yes",
            hashmap! {
                "trebuchet" => hashmap!{
                    "secret" => vec!["nou"],
                    "cache" => vec!["/tmp/cache"]
                },
                "ballista" =>  hashmap!{"secret" => vec!["yes"]},
            },
        ),
    ];
    for (input, expected) in good_cases {
        match Opts::parse_server_transport_options(input) {
            Ok(opts) => {
                // Convert all &str to String to keep tests readable
                let expected_opts = Opts(
                    expected
                        .iter()
                        .map(|(opt_key, args)| {
                            (
                                opt_key.to_string(),
                                Args(
                                    args.iter()
                                        .map(|(k, vs)| {
                                            (
                                                k.to_string(),
                                                vs.iter().map(|v| v.to_string()).collect(),
                                            )
                                        })
                                        .collect(),
                                ),
                            )
                        })
                        .collect(),
                );
                assert_eq!(
                    opts, expected_opts,
                    "{} → {:?} (expected {:?})",
                    input, opts, expected
                )
            }
            Err(err) => panic!("{:?} unexpectedly returned error {}", input, err),
        }
    }
}

#[test]
fn parse_bad_server_transport_options() {
    let bad_cases = [
        "t\\",
        ":=",
        "t:=",
        ":k=",
        ":=v",
        "t:=v",
        "t:=v",
        "t:k\\",
        "t:k=v;",
        "abc",
        "t:",
        "key=value",
        "=value",
        "t:k=v\\",
        "t1:k=v;t2:k=v\\",
        "t:=key=value",
        "t:==key=value",
        "t:;key=value",
        "t:key\\=value",
    ];

    for input in bad_cases {
        if Opts::parse_server_transport_options(input).is_ok() {
            panic!("{} unexpectedly succeeded", input)
        }
    }
}

/// Regression: `parse_server_transport_options` used `s.chars().nth(i)` where
/// `i` is a *byte* index. With multi-byte method names the char-based lookup
/// either compared the wrong character or panicked on `None`. After the fix
/// we index the byte directly (`s.as_bytes()[i]`), which is correct because
/// the terminators (`:`, `=`, `;`) are single-byte ASCII.
#[test]
fn parse_server_transport_options_multibyte_method_name() {
    // "éé" is 4 bytes in UTF-8 (each é = 0xC3 0xA9).
    // Before the fix, byte index 4 was passed to `chars().nth(4)` which
    // yielded `None` (only 2 chars) → unwrap panic.
    let input = "éé:key=val";
    let result = Opts::parse_server_transport_options(input);
    assert!(
        result.is_ok(),
        "multi-byte method name should parse successfully, got: {result:?}"
    );
    let opts = result.unwrap();
    let args = opts.get("éé").expect("expected method 'éé' in parsed opts");
    assert_eq!(
        args.retrieve("key").as_deref(),
        Some("val"),
        "key should map to 'val'"
    );
}

/// Multi-byte characters in the *value* position should also round-trip.
#[test]
fn parse_server_transport_options_multibyte_value() {
    let input = "t:k=Ω";
    let result = Opts::parse_server_transport_options(input);
    assert!(
        result.is_ok(),
        "multi-byte value should parse, got: {result:?}"
    );
    let opts = result.unwrap();
    let args = opts.get("t").expect("expected method 't'");
    assert_eq!(args.retrieve("k").as_deref(), Some("Ω"));
}

/// Multi-byte in method, key, AND value combined.
#[test]
fn parse_server_transport_options_multibyte_all_positions() {
    let input = "café:naïve=über";
    let result = Opts::parse_server_transport_options(input);
    assert!(
        result.is_ok(),
        "fully multi-byte input should parse, got: {result:?}"
    );
    let opts = result.unwrap();
    let args = opts.get("café").expect("expected method 'café'");
    assert_eq!(args.retrieve("naïve").as_deref(), Some("über"));
}

#[test]
fn test_encode_smethod_args() {
    let tests = [
        // (None, ""),
        (
            hashmap! {"j"=>vec!["v1", "v2", "v3"], "k"=>vec!["v1", "v2", "v3"]},
            "j=v1,j=v2,j=v3,k=v1,k=v2,k=v3",
        ),
        (
            hashmap! {"=,\\"=>vec!["=", ",", "\\"]},
            "\\=\\,\\\\=\\=,\\=\\,\\\\=\\,,\\=\\,\\\\=\\\\",
        ),
        (
            hashmap! {""=>vec!["", "é"], "a"=>vec!["", "a,b"]},
            "=,=é,a=,a=a\\,b",
        ),
        (hashmap! {"secret"=>vec!["yes"]}, "secret=yes"),
        (
            hashmap! {"secret"=> vec!["nou"], "cache" => vec!["/tmp/cache"]},
            "cache=/tmp/cache,secret=nou",
        ),
        // (HashMap::new(), ""),
    ];

    assert_eq!("", Args::new().encode_smethod_args());

    for (input_map, expected) in tests.iter() {
        let input = Args(
            input_map
                .iter()
                .map(|(k, vs)| (k.to_string(), vs.iter().map(|v| v.to_string()).collect()))
                .collect(),
        );

        let encoded = input.encode_smethod_args();
        assert_eq!(
            &encoded, expected,
            "{:?} → {} (expected {})",
            input, encoded, expected
        );

        let mut smethod = String::from("ARGS:");
        smethod.push_str(&encoded);
        let m = parse_smethod_args(&smethod).unwrap();
        assert!(!m.is_empty(), "{:?} -> {}", input_map, encoded);
        // println!("{} → {:?}", encoded, m);
    }
}

fn parse_smethod_args(args: impl AsRef<str>) -> Result<HashMap<String, String>, Cow<'static, str>> {
    let words = args.as_ref().split_whitespace();

    let mut parsed_args = HashMap::new();

    // NOTE(eta): pt-spec.txt seems to imply these options can't contain spaces, so
    //            we work under that assumption.
    //            It also doesn't actually parse them out -- but seeing as the API to
    //            feed these back in will want them as separated k/v pairs, I think
    //            it makes sense to here.
    for option in words {
        if let Some(mut args) = option.strip_prefix("ARGS:") {
            while !args.is_empty() {
                let (k, v, rest) = parse_one_smethod_arg(args)
                    .map_err(|e| Cow::from(format!("failed to parse SMETHOD ARGS: {}", e)))?;
                if parsed_args.contains_key(&k) {
                    // At least check our assumption that this is actually k/v
                    // and not Vec<(String, String)>.
                    warn!("PT SMETHOD arguments contain repeated key {}!", k);
                }
                parsed_args.insert(k, v);
                args = rest;
            }
        }
    }

    Ok(parsed_args)
}

/// Chomp one key/value pair off a list of smethod args.
/// Returns (k, v, unparsed rest of string).
/// Will also chomp the comma at the end, if there is one.
///
/// From `pt-spec.txt #3.3.3`:
/// ```txt
/// ARGS:[<Key>=<Value>,]+[<Key>=<Value>]
///
///   The "ARGS" option is used to pass additional key/value
///   formatted information that clients will require to use
///   the reverse proxy.
///
///   Equal signs and commas MUST be escaped with a backslash.
///
///   Tor: The ARGS are included in the transport line of the
///   Bridge's extra-info document.
///
/// ```
fn parse_one_smethod_arg(args: &str) -> Result<(String, String, &str), &'static str> {
    // NOTE(eta): Apologies for this looking a bit gnarly. Ideally, this is what you'd use
    //            something like `nom` for, but I didn't want to bring in a dep just for this.

    let mut key = String::new();
    let mut val = String::new();
    // If true, we're reading the value, not the key.
    let mut reading_val = false;
    let mut chars = args.chars();
    while let Some(c) = chars.next() {
        let target = if reading_val { &mut val } else { &mut key };
        match c {
            '\\' => {
                let c = chars
                    .next()
                    .ok_or("smethod arg terminates with backslash")?;
                target.push(c);
            }
            '=' => {
                if reading_val {
                    return Err("encountered = while parsing value");
                }
                reading_val = true;
            }
            ',' => break,
            c => target.push(c),
        }
    }
    if !reading_val {
        return Err("ran out of chars parsing smethod arg");
    }
    Ok((key, val, chars.as_str()))
}
