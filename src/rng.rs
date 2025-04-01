use frost_p256::rand_core::{CryptoRng, Error, RngCore as FrostRngCore};
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::RngCore;
use rand_chacha::rand_core::TryRngCore;

/// Use rand v0.9 RNG in rand v0.6.
pub(crate) struct ReproducibleRng<'a>(pub &'a mut ChaCha20Rng);

impl <'a> CryptoRng for ReproducibleRng<'a> {}

impl <'a> FrostRngCore for ReproducibleRng<'a> {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        Ok(self.0.try_fill_bytes(dest).expect("infallible"))
    }
}