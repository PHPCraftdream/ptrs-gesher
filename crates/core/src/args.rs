//! Key–value mappings for the representation of client and server options.

use std::collections::HashMap;

use crate::Error;

/// Private pattern used for counting
///
/// This is a way to force the type as slice of ()
/// turns array into slice then calls slice implementation of len
///
/// This is evaluated at compile time so there are no more allocations
/// to run the macro. Unit () is a zero size type.
///
/// (<[()]>)::len(...)    - treat this as a Unit slice and the take the length
///
/// The (@single ...) target pattern allows us to substitute Units for whatever
/// object is in the expr so we can count with a const object that doesn't
/// require an allocation. See
/// [The Little Book of Rust Macros](https://veykril.github.io/tlborm/decl-macros/building-blocks/counting.html)
/// for more detail.
#[doc(hidden)]
#[cfg(test)]
macro_rules! count {
    (@single $($x:tt)*) => (());
    (@count $($rest:expr),*) => (<[()]>::len(&[$(count!(@single $rest)),*]));
}

/// Create an **Args** object from a list of key-value pairs
///
/// ## Example
///
/// ```text
/// # #[macro_use] extern crate ptrs;
/// # fn main() {
///
/// let map = args!{
///     "a" => 1,
///     "b" => 2,
/// };
/// assert_eq!(map["a"], 1);
/// assert_eq!(map["b"], 2);
/// assert_eq!(map.get("c"), None);
/// # }
/// ```
///
/// This macro is crate-internal (used by tests and helpers); it is not part of
/// the public API.
#[cfg(test)]
macro_rules! args {
    ($($key:expr => $value:expr,)+) => { args!($($key => $value),+) };
    ($($key:expr => $value:expr),*) => {
        {
            let _cap = count!(@count $($key),*);
            let mut _map = ::std::collections::HashMap::with_capacity(_cap);
            $(
                let _ = _map.insert($key.to_string(), $value.iter().map(|s| s.to_string()).collect());
            )*
            Args(_map)
        }
    };
}

/// Create a **HashMap** from a list of key-value pairs
#[doc(hidden)]
#[cfg(test)]
macro_rules! hashmap {
    ($($key:expr => $value:expr,)+) => { hashmap!($($key => $value),+) };
    ($($key:expr => $value:expr),*) => {
        {
            let _cap = count!(@count $($key),*);
            let mut _map = ::std::collections::HashMap::with_capacity(_cap);
            $(
                let _ = _map.insert($key, $value);
            )*
            _map
        }
    };
}

/// Arguments maintained as a map of string keys to a list of values.
/// It is similar to url.Values.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Args(pub(crate) HashMap<String, Vec<String>>);

impl Args {
    /// Create an empty `Args` bag.
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    /// Add a key-value pair. Appends to existing values for the same key.
    pub fn add(&mut self, key: &str, value: &str) {
        self.add_owned(key.to_owned(), value.to_owned());
    }

    fn add_owned(&mut self, key: String, value: String) {
        self.0.entry(key).or_default().push(value);
    }

    fn from_owned(key: String, value: String) -> Self {
        let mut args = Self(HashMap::with_capacity(1));
        args.add_owned(key, value);
        args
    }

    /// Get the list of values for a key, or `None` if the key is absent.
    pub fn get(&self, key: &str) -> Option<&Vec<String>> {
        self.0.get(key)
    }

    /// Whether a key is present.
    pub fn contains_key(&self, key: &str) -> bool {
        self.0.contains_key(key)
    }

    /// Whether this bag contains no keys.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Number of keys in this bag.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Iterate over the key / value-list pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &Vec<String>)> {
        self.0.iter()
    }

    /// Retrieve the first value for a key, or `None` if absent / empty.
    pub fn retrieve(&self, key: impl AsRef<str>) -> Option<String> {
        let v = self.0.get(key.as_ref())?;
        if v.is_empty() {
            return None;
        }
        Some(v[0].clone())
    }

    /// Parse a name–value mapping as from an encoded SOCKS username/password.
    ///
    /// From `pt-spec.txt`:
    ///
    /// "First the `Key=Value` formatted arguments MUST be escaped, such that all
    /// backslash, equal sign, and semicolon characters are escaped with a
    /// backslash.
    ///
    /// Second, all of the escaped are concatenated together."
    ///
    /// Example: `shared-secret=rahasia;secrets-file=/tmp/blob`
    ///
    /// Semicolons delimit pairs; commas remain part of values.
    pub fn parse_client_parameters(params: &str) -> Result<Self, Error> {
        Self::parse_delimited(params, ';', "client params")
    }

    /// Parse the comma-separated arguments carried by an SMETHOD `ARGS:` field.
    ///
    /// The optional `ARGS:` prefix is accepted for convenience. Commas delimit
    /// pairs in this format; semicolons and other punctuation remain part of a
    /// value unless escaped according to the PT specification.
    pub fn parse_smethod_args(params: &str) -> Result<Self, Error> {
        let params = params.strip_prefix("ARGS:").unwrap_or(params);
        Self::parse_delimited(params, ',', "SMETHOD args")
    }

    fn parse_delimited(params: &str, delimiter: char, description: &str) -> Result<Self, Error> {
        let mut args = Args::new();
        if params.is_empty() {
            return Ok(args);
        }

        let mut remaining = params;
        loop {
            // Read the key.
            let (offset, key) = index_unescaped(remaining, &['=', delimiter])?;

            // End of string or no equals sign?
            if offset >= remaining.len() || !remaining[offset..].starts_with('=') {
                return Err(Error::ParseError(format!(
                    "parsing {description} found no equals sign in {}",
                    &remaining[..offset]
                )));
            }

            // Skip past key + '='
            remaining = &remaining[offset + 1..];

            // Read the value.
            let (offset, value) = index_unescaped(remaining, &[delimiter])?;

            if key.is_empty() {
                return Err(Error::ParseError(format!(
                    "parsing {description} encountered empty key in ={}",
                    &remaining[..offset]
                )));
            }
            args.add_owned(key, value);

            remaining = &remaining[offset..];

            if remaining.is_empty() {
                break;
            }

            // Skip the delimiter (';' or ',')
            remaining = &remaining[1..];
        }

        Ok(args)
    }

    /// Encode a name–value mapping so that it is suitable to go in the ARGS option
    /// of an SMETHOD line. The output is sorted by key. The "ARGS:" prefix is not
    /// added.
    ///
    /// "Equal signs and commas [and backslashes] MUST be escaped with a backslash."
    /// Use [`parse_smethod_args`](Self::parse_smethod_args) to decode this
    /// representation.
    pub fn encode_smethod_args(&self) -> String {
        self.encode_delimited(',', &['=', ','])
    }

    /// Encode a name–value mapping for SOCKS authentication parameters.
    ///
    /// Pairs are separated by semicolons and the output is sorted by key. The
    /// returned string does not include a protocol-specific prefix.
    pub fn encode_client_parameters(&self) -> String {
        self.encode_delimited(';', &['=', ';'])
    }

    fn encode_delimited(&self, delimiter: char, escaped: &[char]) -> String {
        if self.is_empty() {
            return String::new();
        }

        let mut entries: Vec<_> = self.iter().collect();
        entries.sort_unstable_by(|left, right| left.0.cmp(right.0));

        let pair_count = self.0.values().map(Vec::len).sum::<usize>();
        let capacity = self
            .0
            .iter()
            .map(|(key, values)| {
                key.len()
                    .saturating_mul(values.len())
                    .saturating_add(values.iter().map(String::len).sum::<usize>())
            })
            .sum::<usize>()
            .saturating_add(pair_count.saturating_mul(2))
            .saturating_sub(1);
        let mut encoded = String::with_capacity(capacity);

        let mut first = true;
        for (key, values) in entries {
            for value in values {
                if !first {
                    encoded.push(delimiter);
                }
                first = false;
                push_backslash_escaped(&mut encoded, key, escaped);
                encoded.push('=');
                push_backslash_escaped(&mut encoded, value, escaped);
            }
        }
        encoded
    }
}

fn push_backslash_escaped(output: &mut String, s: &str, set: &[char]) {
    for c in s.chars() {
        if c == '\\' || set.contains(&c) {
            output.push('\\');
        }
        output.push(c);
    }
}

/// Return the index of the next unescaped byte in s that is in the term set, or
/// else the length of the string if no terminators appear. Additionally return
/// the unescaped string up to the returned index.
fn index_unescaped(s: &str, term: &[char]) -> Result<(usize, String), Error> {
    let mut unesc = String::new();
    let mut chars = s.char_indices();
    let mut i: usize;
    while let Some((byte_pos, c)) = chars.next() {
        i = byte_pos;

        if term.contains(&c) {
            return Ok((i, unesc));
        }
        if c == '\\' {
            match chars.next() {
                Some((_next_pos, next_c)) => {
                    unesc.push(next_c);
                    continue;
                }
                None => {
                    return Err(Error::ParseError(format!(
                        "nothing following final escape in \"{}\"",
                        s
                    )));
                }
            }
        }
        unesc.push(c);
    }
    Ok((s.len(), unesc))
}

/// transport name to value mapping as from TOR_PT_SERVER_TRANSPORT_OPTIONS
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Opts(HashMap<String, Args>);

impl Opts {
    /// Create an empty `Opts` bag.
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    /// Parse a transport–name–value mapping as from TOR_PT_SERVER_TRANSPORT_OPTIONS.
    ///
    /// "...a semicolon-separated list of `key`:`value` pairs, where `key` is a PT
    /// name and `value` is a k=v string value with options that are to be passed to
    /// the transport. Colons, semicolons, equal signs and backslashes must be
    /// escaped with a backslash."
    ///
    /// Example:
    /// ```text
    /// # use std::collections::HashMap;
    /// use ptrs::{args, args::{Opts, Args}};
    /// let input = "scramblesuit:key=banana;automata:rule=110;automata:depth=3";
    /// let mut expected = HashMap::new();
    /// expected.insert(String::from("scramblesuit"), args!{"key"=> vec!["banana"]});
    /// expected.insert(String::from("automata"), args!{"rule"=> vec!["110"], "depth" => vec!["3"]});
    ///
    /// match Opts::parse_server_transport_options(input) {
    ///     Ok(map) => assert_eq!(map, expected),
    ///     Err(e) => panic!("{}", e),
    /// }
    ///
    /// ```
    /// From `pt-spec.txt`:
    ///
    /// ```txt
    /// "TOR_PT_SERVER_TRANSPORT_OPTIONS"
    ///
    ///        Specifies per-PT protocol configuration directives, as a
    ///        semicolon-separated list of <key>:<value> pairs, where <key>
    ///        is a PT name and <value> is a k=v string value with options
    ///        that are to be passed to the transport.
    ///
    ///        Colons, semicolons, and backslashes MUST be
    ///        escaped with a backslash.
    ///
    ///        If there are no arguments that need to be passed to any of
    ///        PT transport protocols, "TOR_PT_SERVER_TRANSPORT_OPTIONS"
    ///        MAY be omitted.
    ///
    ///        Example:
    ///
    ///          TOR_PT_SERVER_TRANSPORT_OPTIONS=scramblesuit:key=banana;automata:rule=110;automata:depth=3
    ///
    ///          Will pass to 'scramblesuit' the parameter 'key=banana' and to
    ///          'automata' the arguments 'rule=110' and 'depth=3'.
    /// ```
    pub fn parse_server_transport_options(s: &str) -> Result<Self, Error> {
        let mut opts = Opts::new();
        if s.is_empty() {
            return Ok(opts);
        }
        let mut i: usize = 0;
        loop {
            let begin = i;
            // Read the method name.
            let (offset, method_name) = index_unescaped(&s[i..], &[':', '=', ';'])?;

            i += offset;
            // End of string or no colon?
            // `i` is a byte index (accumulated from `index_unescaped` which uses
            // `char_indices`). Compare against the raw byte, not the i-th *character*,
            // to avoid misindexing on multi-byte UTF-8 input. The terminators are
            // ASCII, so a single-byte comparison is correct and avoids O(n) rescanning.
            if i >= s.len() || s.as_bytes()[i] != b':' {
                return Err(Error::ParseError(format!("no colon in {}", &s[begin..i])));
            }
            // Skip the colon.
            i += 1;

            // Read the key.
            let (offset, key) = index_unescaped(&s[i..], &['=', ';'])?;

            i += offset;
            // End of string or no equals sign?
            // Same byte-vs-char rationale as the colon check above.
            if i >= s.len() || s.as_bytes()[i] != b'=' {
                return Err(Error::ParseError(format!(
                    "no equals sign in {}",
                    &s[begin..i]
                )));
            }
            // Skip the equals sign.
            i += 1;

            // Read the value.
            let (offset, value) = index_unescaped(&s[i..], &[';'])?;

            i += offset;
            if method_name.is_empty() {
                return Err(Error::ParseError(format!(
                    "empty method name in {}",
                    &s[begin..i]
                )));
            }
            if key.is_empty() {
                return Err(Error::ParseError(format!("empty key in {}", &s[begin..i])));
            }

            match opts.0.entry(method_name) {
                std::collections::hash_map::Entry::Occupied(mut entry) => {
                    entry.get_mut().add_owned(key, value);
                }
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(Args::from_owned(key, value));
                }
            }

            if i >= s.len() {
                break;
            }
            // Skip the semicolon.
            i += 1;
        }
        Ok(opts)
    }
}

impl Opts {
    /// Get the `Args` for a transport name, or `None` if absent.
    pub fn get(&self, key: &str) -> Option<&Args> {
        self.0.get(key)
    }

    /// Whether a transport name is present.
    pub fn contains_key(&self, key: &str) -> bool {
        self.0.contains_key(key)
    }

    /// Whether this bag contains no transports.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Number of transports in this bag.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Iterate over the (transport-name, `Args`) pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &Args)> {
        self.0.iter()
    }

    /// Remove and return the `Args` for a transport name, if present.
    pub fn remove(&mut self, key: &str) -> Option<Args> {
        self.0.remove(key)
    }
}

impl std::str::FromStr for Args {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse_client_parameters(s)
    }
}

#[cfg(test)]
mod tests;
