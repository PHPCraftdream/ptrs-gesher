pub(crate) struct FakePRNG<'a> {
    bytes: &'a [u8],
}
impl<'a> FakePRNG<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }
}
use rand_core::{utils, Infallible, Rng, TryCryptoRng, TryRng};

impl TryRng for FakePRNG<'_> {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> std::result::Result<u32, Infallible> {
        utils::next_word_via_fill(self)
    }
    fn try_next_u64(&mut self) -> std::result::Result<u64, Infallible> {
        utils::next_word_via_fill(self)
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> std::result::Result<(), Infallible> {
        // assert!(dest.len() <= self.bytes.len(), "dst:{} > have:{}", dest.len(), self.bytes.len());
        if dest.len() > self.bytes.len() {
            let mut rng = rand::rng();
            rng.fill_bytes(dest);
        } else {
            dest.copy_from_slice(&self.bytes[0..dest.len()]);
            self.bytes = &self.bytes[dest.len()..];
        }
        Ok(())
    }
}
impl TryCryptoRng for FakePRNG<'_> {}
