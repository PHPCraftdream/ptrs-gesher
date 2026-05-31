use super::*;
use crate::{
    common::{
        x25519_elligator2::{PublicRepresentative, REPRESENTATIVE_LENGTH},
        HmacSha256,
    },
    framing::{build_and_marshall, ClientHandshakeMessage, MessageTypes, ServerHandshakeMessage},
};

use ptrs::{debug, trace};
use rand::thread_rng;
use tokio_util::codec::Encoder;

use std::time::Instant;

#[derive(Clone)]
pub(crate) struct HandshakeMaterials {
    pub(crate) identity_keys: Obfs4NtorSecretKey,
    pub(crate) session_id: String,
    pub(crate) len_seed: [u8; SEED_LENGTH],
}

impl HandshakeMaterials {
    pub fn get_hmac(&self) -> HmacSha256 {
        let mut key = self.identity_keys.pk.pk.as_bytes().to_vec();
        key.append(&mut self.identity_keys.pk.id.as_bytes().to_vec());
        HmacSha256::new_from_slice(&key[..]).unwrap()
    }

    pub fn new(
        identity_keys: &Obfs4NtorSecretKey,
        session_id: String,
        len_seed: [u8; SEED_LENGTH],
    ) -> Self {
        HandshakeMaterials {
            identity_keys: identity_keys.clone(),
            session_id,
            len_seed,
        }
    }
}

impl Server {
    /// Perform a server-side ntor handshake.
    ///
    /// On success returns a key generator and a server onionskin.
    pub(super) fn server_handshake_obfs4<T>(
        &self,
        msg: T,
        materials: HandshakeMaterials,
    ) -> RelayHandshakeResult<(NtorHkdfKeyGenerator, Vec<u8>)>
    where
        T: AsRef<[u8]>,
    {
        let rng = thread_rng();
        let session_sk = Keys::ephemeral_from_rng(rng)
            .map_err(into_internal!("failed to derive elligator2 server keypair"))?;

        self.server_handshake_obfs4_no_keygen(session_sk, msg, materials)
    }

    /// Helper: perform a server handshake without generating any new keys.
    pub(crate) fn server_handshake_obfs4_no_keygen<T>(
        &self,
        session_sk: EphemeralSecret,
        msg: T,
        mut materials: HandshakeMaterials,
    ) -> RelayHandshakeResult<(NtorHkdfKeyGenerator, Vec<u8>)>
    where
        T: AsRef<[u8]>,
    {
        if CLIENT_MIN_HANDSHAKE_LENGTH > msg.as_ref().len() {
            Err(RelayHandshakeError::EAgain)?;
        }

        let mut client_hs = match self.try_parse_client_handshake(msg, &mut materials) {
            Ok(chs) => chs,
            Err(Error::HandshakeErr(RelayHandshakeError::EAgain)) => {
                return Err(RelayHandshakeError::EAgain);
            }
            // A replayed handshake is still rejected, but its cause must stay
            // observable to the caller: preserve the distinct variant instead of
            // flattening it into the generic `BadClientHandshake` below, so the
            // public API can tell "seen this MAC before" apart from a malformed
            // or mis-keyed handshake.
            Err(Error::HandshakeErr(RelayHandshakeError::ReplayedHandshake)) => {
                debug!(
                    "{} rejected replayed client handshake",
                    materials.session_id
                );
                return Err(RelayHandshakeError::ReplayedHandshake);
            }
            Err(_e) => {
                debug!(
                    "{} failed to parse client handshake: {_e}",
                    materials.session_id
                );
                return Err(RelayHandshakeError::BadClientHandshake);
            }
        };

        debug!(
            "{} successfully parsed client handshake",
            materials.session_id
        );
        let their_pk = client_hs.get_public();
        let ephem_pub = (&session_sk).into();
        let session_repres = PublicRepresentative::from(&session_sk);

        let xy = session_sk.diffie_hellman(&their_pk);
        let xb = materials.identity_keys.sk.diffie_hellman(&their_pk);

        // Ensure that none of the keys are broken (i.e. equal to zero).
        let okay =
            ct::bool_to_choice(xy.was_contributory()) & ct::bool_to_choice(xb.was_contributory());
        trace!("x {} y {}", hex::encode(their_pk), hex::encode(ephem_pub));

        let (key_seed, authcode) =
            ntor_derive(&xy, &xb, &materials.identity_keys.pk, &their_pk, &ephem_pub)
                .map_err(into_internal!("Error deriving keys"))?;
        trace!(
            "seed: {} auth: {}",
            hex::encode(key_seed.as_slice()),
            hex::encode(authcode)
        );

        let mut keygen = NtorHkdfKeyGenerator::new(key_seed, false);

        let reply =
            self.complete_server_hs(&client_hs, materials, session_repres, &mut keygen, authcode)?;

        if okay.into() {
            Ok((keygen, reply))
        } else {
            Err(RelayHandshakeError::BadClientHandshake)
        }
    }

    pub(crate) fn complete_server_hs(
        &self,
        client_hs: &ClientHandshakeMessage,
        materials: HandshakeMaterials,
        session_repres: PublicRepresentative,
        keygen: &mut NtorHkdfKeyGenerator,
        authcode: Authcode,
    ) -> RelayHandshakeResult<Vec<u8>> {
        let epoch_hr = client_hs.get_epoch_hr();

        // Since the current and only implementation always sends a PRNG seed for
        // the length obfuscation, this makes the amount of data received from the
        // server inconsistent with the length sent from the client.
        //
        // Re-balance this by tweaking the client minimum padding/server maximum
        // padding, and sending the PRNG seed unpadded (As in, treat the PRNG seed
        // as part of the server response).  See inlineSeedFrameLength in
        // handshake_ntor.go.

        // Generate/send the response.
        let mut sh_msg = ServerHandshakeMessage::new(session_repres, authcode, epoch_hr);

        let h = materials.get_hmac();
        let mut buf = BytesMut::with_capacity(MAX_HANDSHAKE_LENGTH);
        sh_msg
            .marshall(&mut buf, h)
            .map_err(|e| RelayHandshakeError::FrameError(format!("{e}")))?;
        trace!("adding encoded prng seed");

        // Send the PRNG seed as part of the first packet.
        let mut prng_pkt_buf = BytesMut::new();
        build_and_marshall(
            &mut prng_pkt_buf,
            MessageTypes::PrngSeed.into(),
            materials.len_seed,
            0,
        )
        .map_err(|e| RelayHandshakeError::FrameError(format!("{e}")))?;

        let codec = &mut keygen.codec;
        codec
            .encode(prng_pkt_buf.clone(), &mut buf)
            .map_err(|e| RelayHandshakeError::FrameError(format!("{e}")))?;

        debug!(
            "{} writing server handshake {}B ...{}",
            materials.session_id,
            buf.len(),
            hex::encode(&buf[buf.len() - 10..]),
        );

        Ok(buf.to_vec())
    }

    /// Production entry point: parse a client handshake against the *current*
    /// wall-clock epoch hour.
    ///
    /// This is a thin wrapper around [`Self::try_parse_client_handshake_at`]
    /// that supplies the real epoch hour. Keeping the time source in this single
    /// line (and out of the parsing core) is what makes the ±1h MAC slack window
    /// deterministically testable: tests drive the core with an explicit
    /// `server_epoch_hour` instead of `SystemTime::now()`. The public API and the
    /// window width are unchanged — only the seam moved.
    fn try_parse_client_handshake(
        &self,
        buf: impl AsRef<[u8]>,
        materials: &mut HandshakeMaterials,
    ) -> Result<ClientHandshakeMessage> {
        self.try_parse_client_handshake_at(buf, materials, get_epoch_hour())
    }

    /// Core of client-handshake parsing, with the server's "current" epoch hour
    /// injected as `server_epoch_hour`.
    ///
    /// INVARIANT (security-critical): the client folds an epoch-hour string `E`
    /// into its handshake MAC but does *not* transmit `E` on the wire. The server
    /// therefore cannot read `E` directly; it reproduces the MAC for each of the
    /// candidate hours `server_epoch_hour + offset` for `offset ∈ {0, -1, +1}`
    /// and accepts iff one of them matches in constant time. That `{-1, 0, +1}`
    /// set *is* the ±1h clock-desync slack window. Widening it enlarges the
    /// replay / anti-probing surface; narrowing it causes spurious rejections of
    /// honest clients whose clock differs by up to an hour. The offset set must
    /// not change.
    ///
    /// `server_epoch_hour` is the base hour around which those offsets are tried
    /// — i.e. the value that production reads from `get_epoch_hour()`.
    pub(crate) fn try_parse_client_handshake_at(
        &self,
        buf: impl AsRef<[u8]>,
        materials: &mut HandshakeMaterials,
        server_epoch_hour: u64,
    ) -> Result<ClientHandshakeMessage> {
        let buf = buf.as_ref();
        let mut h = materials.get_hmac();

        if CLIENT_MIN_HANDSHAKE_LENGTH > buf.len() {
            Err(Error::HandshakeErr(RelayHandshakeError::EAgain))?;
        }

        let r_bytes: [u8; 32] = buf[0..REPRESENTATIVE_LENGTH].try_into().unwrap();

        // derive the mark based on the literal bytes on the wire
        h.update(&r_bytes[..]);

        // The elligator library internally clears the high-order bits of the
        // representative to force a LSR value, but we use the wire format for
        // deriving the mark (i.e. without cleared bits).
        let repres = PublicRepresentative::from(&r_bytes);

        let m = h.finalize_reset().into_bytes();
        let mark: [u8; MARK_LENGTH] = m[..MARK_LENGTH].try_into()?;

        trace!("{} mark?:{}", materials.session_id, hex::encode(mark));

        // find mark + mac position
        let pos = match find_mac_mark(
            mark,
            buf,
            REPRESENTATIVE_LENGTH + CLIENT_MIN_PAD_LENGTH,
            MAX_HANDSHAKE_LENGTH,
            true,
        ) {
            Some(p) => p,
            None => {
                trace!("{} didn't find mark", materials.session_id);
                if buf.len() > MAX_HANDSHAKE_LENGTH {
                    Err(Error::HandshakeErr(RelayHandshakeError::BadClientHandshake))?
                }
                Err(Error::HandshakeErr(RelayHandshakeError::EAgain))?
            }
        };

        // validate he MAC
        let mut mac_found = false;
        let mut epoch_hr = String::new();
        for offset in [0_i64, -1, 1] {
            // Allow the epoch to be off by up to one hour in either direction.
            // The offset set {0, -1, +1} is the ±1h slack window (see the
            // function-level INVARIANT) — do not widen or narrow it. The base
            // hour is injected so this window is testable without wall-clock.
            trace!("server trying offset: {offset}");
            let eh = format!("{}", offset + server_epoch_hour as i64);

            h.reset();
            h.update(&buf[..pos + MARK_LENGTH]);
            h.update(eh.as_bytes());
            let mac_calculated = &h.finalize_reset().into_bytes()[..MAC_LENGTH];
            let mac_received = &buf[pos + MARK_LENGTH..pos + MARK_LENGTH + MAC_LENGTH];
            trace!(
                "server {}-{}",
                hex::encode(mac_calculated),
                hex::encode(mac_received)
            );
            if mac_calculated.ct_eq(mac_received).into() {
                trace!("correct mac");
                // Ensure that this handshake has not been seen previously.
                if self
                    .0
                    .replay_filter
                    .test_and_set(Instant::now(), mac_received)
                {
                    // The client either happened to generate exactly the same
                    // session key and padding, or someone is replaying a previous
                    // handshake.  In either case, fuck them.
                    Err(Error::HandshakeErr(RelayHandshakeError::ReplayedHandshake))?
                }

                epoch_hr = eh;
                mac_found = true;
                // we could break here, but in the name of reducing timing
                // variance, we just evaluate all three MACs.
            }
        }
        if !mac_found {
            // This could be a [`RelayHandshakeError::TagMismatch`] :shrug:
            Err(Error::HandshakeErr(RelayHandshakeError::BadClientHandshake))?
        }

        // client should never send any appended padding at the end.
        if buf.len() != pos + MARK_LENGTH + MAC_LENGTH {
            Err(Error::HandshakeErr(RelayHandshakeError::BadClientHandshake))?
        }

        Ok(ClientHandshakeMessage::new(
            repres, 0, // pad_len doesn't matter when we are reading client handshake msg
            epoch_hr,
        ))
    }
}

#[cfg(test)]
mod epoch_window_tests {
    //! Deterministic coverage of the server's ±1h epoch MAC slack window.
    //!
    //! The client bakes an epoch-hour string `E` into its handshake MAC but
    //! never sends `E` on the wire, so the server reproduces the MAC for the
    //! candidate hours `base + {0, -1, +1}` and accepts iff one matches. This
    //! test pins that window directly: with a client hello built for a fixed
    //! `E`, the server accepts when its injected base hour is `E`, `E-1`, or
    //! `E+1` (the slack), and rejects at `E-2` / `E+2` (just outside). It uses
    //! the injected-base seam (`try_parse_client_handshake_at`) so it needs
    //! neither the network nor the real clock.

    use super::*;
    use crate::common::x25519_elligator2::{EphemeralSecret, Keys};
    use rand::rngs::OsRng;

    /// Reproduce the exact client-hello wire format
    /// `X | P_C | M_C | MAC(X | P_C | M_C | E)` for an explicit epoch hour `E`.
    ///
    /// We can't go through `ClientHandshakeMessage::marshall`, because that
    /// overwrites the epoch hour with `get_epoch_hour()` at marshal time, which
    /// is exactly the wall-clock dependency this test is designed to avoid. So
    /// we build the bytes here with `E` chosen by the caller, mirroring
    /// `framing::handshake::ClientHandshakeMessage::marshall`. `h` must be the
    /// server-identity-keyed HMAC (`materials.get_hmac()`), since the mark/MAC
    /// are keyed by `serverIdentity | NodeID`.
    fn build_client_hello(
        repres: &PublicRepresentative,
        pad_len: usize,
        e: u64,
        mut h: HmacSha256,
    ) -> Vec<u8> {
        // M_C = HMAC(serverIdentity | NodeID, X)
        h.reset();
        h.update(repres.as_bytes().as_ref());
        let mark = h.finalize_reset().into_bytes()[..MARK_LENGTH].to_vec();

        let pad = make_hs_pad(pad_len).expect("test padding generation");

        // X | P_C | M_C
        let mut params = Vec::new();
        params.extend_from_slice(repres.as_bytes());
        params.extend_from_slice(&pad);
        params.extend_from_slice(&mark);

        // MAC = HMAC(serverIdentity | NodeID, X | P_C | M_C | E)
        h.update(&params);
        h.update(format!("{e}").as_bytes());
        let mac = h.finalize_reset().into_bytes()[..MAC_LENGTH].to_vec();

        let mut hello = params;
        hello.extend_from_slice(&mac);
        hello
    }

    /// Build a fresh server + a client hello keyed to it, for a chosen epoch
    /// hour `E`. A fresh `Server` (hence fresh replay filter) is returned with
    /// each call so the replay filter never confuses the window assertions:
    /// the same MAC accepted at `base = E` would otherwise be rejected as a
    /// replay when re-checked at `base = E±1`.
    fn server_and_hello_for_epoch(e: u64) -> (Server, Vec<u8>, HandshakeMaterials) {
        let mut rng = OsRng;
        let identity = Obfs4NtorSecretKey::generate_for_test(&mut rng);
        let server = Server::new_from_key(identity.clone());

        let materials =
            HandshakeMaterials::new(&identity, "epoch-window-test".into(), [0u8; SEED_LENGTH]);

        // A real elligator2 ephemeral so the representative is on the wire form
        // the server expects; the DH result is irrelevant to MAC validation.
        let ephem: EphemeralSecret = Keys::ephemeral_from_rng(rng).expect("ephemeral key");
        let repres = PublicRepresentative::from(&ephem);

        // Padding must satisfy the server's minimum-handshake-length checks.
        let hello = build_client_hello(&repres, CLIENT_MIN_PAD_LENGTH, e, materials.get_hmac());
        (server, hello, materials)
    }

    /// Helper: does the server accept this hello when its base hour is `base`?
    /// Returns `Ok(())` on accept, `Err(variant)` on the rejection variant.
    fn parse_at(
        server: &Server,
        hello: &[u8],
        mut materials: HandshakeMaterials,
        base: u64,
    ) -> Result<()> {
        server
            .try_parse_client_handshake_at(hello, &mut materials, base)
            .map(|_| ())
    }

    /// The fixed client epoch hour used across the window assertions. A concrete
    /// historical value (2021-07-01T00:00 UTC / 3600) keeps the test fully
    /// independent of the real clock.
    const E: u64 = 1_625_097_600 / 3600;

    #[test]
    fn epoch_hour_exact_match_accepted() {
        let (server, hello, mat) = server_and_hello_for_epoch(E);
        parse_at(&server, &hello, mat, E).expect("hello built for E must be accepted at base=E");
    }

    #[test]
    fn epoch_hour_within_slack_accepted() {
        // base = E-1 and base = E+1 are the inclusive edges of the ±1h window:
        // the client's E lands at the server's +1 / -1 offset respectively.
        for base in [E - 1, E + 1] {
            let (server, hello, mat) = server_and_hello_for_epoch(E);
            parse_at(&server, &hello, mat, base).unwrap_or_else(|e| {
                panic!("hello for E must be accepted at base={base} (slack edge), got {e:?}")
            });
        }
    }

    #[test]
    fn epoch_hour_outside_slack_rejected_as_bad_client_handshake() {
        // base = E-2 and base = E+2 are one hour past the window: the candidate
        // hours {base-1, base, base+1} never include E, so no MAC matches and
        // the parse fails with the specific BadClientHandshake variant (the
        // no-MAC-found arm), not some unrelated error. If the window were ever
        // widened to ±2h these would start being accepted and this test fails.
        for base in [E - 2, E + 2] {
            let (server, hello, mat) = server_and_hello_for_epoch(E);
            match parse_at(&server, &hello, mat, base) {
                Err(Error::HandshakeErr(RelayHandshakeError::BadClientHandshake)) => {}
                other => panic!(
                    "hello for E must be rejected at base={base} (outside ±1h) with \
                     HandshakeErr(BadClientHandshake); got: {other:?}"
                ),
            }
        }
    }
}
