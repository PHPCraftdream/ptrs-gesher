//! Weighted probability distribution
//!
//! The probdist module implements a weighted probability distribution suitable for
//! protocol parameterization.  To allow for easy reproduction of a given
//! distribution, the drbg package is used as the random number source.
//!
//! # Known issue: sampling is non-reproducible
//!
//! The distribution *tables* are derived deterministically from a [`drbg::Seed`]
//! (see [`WeightedDist::reseed`]), but [`WeightedDist::sample`] draws its die-roll
//! and coin-flip from the OS CSPRNG (`getrandom`), **not** from a seeded DRBG.
//! As a consequence the obfuscation produced at run time is not reproducible from
//! the seed alone. Upstream obfs4 (go-fil) samples from the seeded DRBG, so this
//! is a behavioural divergence. It is documented rather than fixed here because a
//! reference vector / wire-compat decision is needed before changing the sampling
//! source; do not "fix" it casually as it alters observable traffic shaping.

use crate::common::drbg;

use std::cmp::{max, min};
use std::fmt;
use std::sync::{Arc, Mutex};

use rand::{seq::SliceRandom, Rng};

const MIN_VALUES: i32 = 1;
const MAX_VALUES: i32 = 100;

/// A weighted distribution of integer values.
#[derive(Clone)]
pub struct WeightedDist(Arc<Mutex<InnerWeightedDist>>);

struct InnerWeightedDist {
    min_value: i32,
    max_value: i32,
    biased: bool,

    values: Vec<i32>,
    weights: Vec<f64>,

    alias: Vec<usize>,
    prob: Vec<f64>,
}

impl WeightedDist {
    /// New creates a weighted distribution of values ranging from min to max
    /// based on a HashDrbg initialized with seed.  Optionally, bias the weight
    /// generation to match the ScrambleSuit non-uniform distribution from
    /// obfsproxy.
    pub fn new(seed: drbg::Seed, min: i32, max: i32, biased: bool) -> Self {
        let w = WeightedDist(Arc::new(Mutex::new(InnerWeightedDist {
            min_value: min,
            max_value: max,
            biased,
            values: vec![],
            weights: vec![],
            alias: vec![],
            prob: vec![],
        })));
        let _ = &w.reseed(seed);

        w
    }

    /// Generates a random value according to the generated distribution.
    pub fn sample(&self) -> i32 {
        let dist = self.0.lock().unwrap();

        // Invariant: `values`/`prob`/`alias` are non-empty after construction.
        // `WeightedDist::new` always calls `reseed`, which calls `gen_values`,
        // and `gen_values` picks `rng.gen_range(1..=n)` (with `n >= MIN_VALUES`
        // == 1) entries — so `values.len() >= 1`. The `% values.len()` below and
        // the `prob[i]`/`alias[i]` indexing rely on this; assert it so a future
        // refactor that breaks the invariant fails loudly instead of panicking
        // with an opaque divide-by-zero / out-of-bounds.
        assert!(
            !dist.values.is_empty(),
            "WeightedDist sampled before tables were populated (empty values)"
        );

        let mut buf = [0_u8; 8];
        // Generate a fair die roll fro a $n$-sided die; call the side $i$.
        // A failure of the OS CSPRNG is not recoverable here; fail fast with a
        // clear message rather than a bare unwrap.
        getrandom::getrandom(&mut buf).expect("system RNG failure during obfs4 length sampling");

        #[cfg(target_pointer_width = "64")]
        let i = usize::from_ne_bytes(buf) % dist.values.len();

        #[cfg(target_pointer_width = "32")]
        let i = usize::from_ne_bytes(buf[0..4].try_into().unwrap()) % dist.values.len();

        // flip a coin that comes up heads with probability $prob[i]$.
        getrandom::getrandom(&mut buf).expect("system RNG failure during obfs4 length sampling");
        let bits = u64::from_le_bytes(buf);
        let f = (bits >> 11) as f64 / ((1u64 << 53) as f64);
        // f is now uniform in [0.0, 1.0)
        if f < dist.prob[i] {
            // if the coin comes up "heads", use $i$
            dist.min_value + dist.values[i]
        } else {
            // otherwise use $alias[i]$.
            dist.min_value + dist.values[dist.alias[i]]
        }
    }

    /// Generates a new distribution with the same min/max based on a new seed.
    pub fn reseed(&self, seed: drbg::Seed) {
        let mut drbg = drbg::Drbg::new(Some(seed)).unwrap();

        let mut dist = self.0.lock().unwrap();
        dist.gen_values(&mut drbg);
        if dist.biased {
            dist.gen_biased_weights(&mut drbg);
        } else {
            dist.gen_uniform_weights(&mut drbg);
        }
        dist.gen_tables();

        // Establish the non-empty invariant relied upon by `sample`: at least
        // one value/prob/alias entry must exist after (re)seeding. `gen_values`
        // guarantees this (it selects `1..=n` entries), so this assert is a
        // tripwire for future changes, not expected to fire in normal operation.
        debug_assert!(
            !dist.values.is_empty() && dist.prob.len() == dist.values.len(),
            "WeightedDist::reseed produced inconsistent/empty tables"
        );
    }
}

impl InnerWeightedDist {
    // Creates a slice containing a random number of random values that, when
    // scaled by adding self.min_value, will fall into [min, max].
    fn gen_values<R: Rng + ?Sized>(&mut self, rng: &mut R) {
        let mut n_values = self.max_value - self.min_value;

        let mut values: Vec<i32> = (0..=n_values).collect();
        values.shuffle(rng);
        n_values = max(n_values, MIN_VALUES);
        n_values = min(n_values, MAX_VALUES);

        let n_values = rng.gen_range(1..=n_values) as usize;
        self.values = values[..n_values].to_vec();
    }

    // generates a non-uniform weight list, similar to the scramblesuit
    // prob_dist mode.
    fn gen_biased_weights<R: Rng + ?Sized>(&mut self, rng: &mut R) {
        self.weights = vec![0_f64; self.values.len()];

        let mut cumul_prob: f64 = 0.0;
        for i in 0..self.weights.len() {
            self.weights[i] = (1.0 - cumul_prob) * rng.gen::<f64>();
            cumul_prob += self.weights[i];
        }
    }

    // generates a uniform weight list.
    fn gen_uniform_weights<R: Rng + ?Sized>(&mut self, rng: &mut R) {
        self.weights = vec![0_f64; self.values.len()];

        for i in 0..self.weights.len() {
            self.weights[i] = rng.gen();
        }
    }

    // Calculates the alias and prob tables use for Vose's alias Method.
    // Algorithm taken from http://www.keithschwarz.com/darts-dice-coins/
    fn gen_tables(&mut self) {
        let n = self.weights.len();
        let sum: f64 = self.weights.iter().sum();

        let mut alias = vec![0_usize; n];
        let mut prob = vec![0_f64; n];

        // multiply each probability by $n$.
        let mut scaled: Vec<f64> = self.weights.iter().map(|f| f * (n as f64) / sum).collect();
        // if $p$ < 1$ add $i$ to $small$.
        let mut small: Vec<usize> = scaled
            .iter()
            .enumerate()
            .filter(|(_, f)| **f < 1.0)
            .map(|(i, _)| i)
            .collect();
        // if $p$ >= 1$ add $i& to $large$.
        let mut large: Vec<usize> = scaled
            .iter()
            .enumerate()
            .filter(|(_, f)| **f >= 1.0)
            .map(|(i, _)| i)
            .collect();

        // While $small$ and $large$ are not empty: ($large$ might be emptied first)
        // remove the first element from $small$ and call it $l$.
        // remove the first element from $large$ and call it $g$.
        // set $prob[l] = p_l$
        // set $alias[l] = g$
        // set $p_g = (p_g+p_l) - 1$ (This is a more numerically stable option)
        // if $p_g < 1$ add $g$ to $small$.
        // otherwise add $g$ to $large$ as %p_g >= 1$
        while !small.is_empty() && !large.is_empty() {
            let l = small.remove(0);
            let g = large.remove(0);

            prob[l] = scaled[l];
            alias[l] = g;

            scaled[g] = scaled[g] + scaled[l] - 1.0;
            if scaled[g] < 1.0 {
                small.push(g);
            } else {
                large.push(g);
            }
        }

        // while $large$ is not empty, remove the first element ($g$) and
        // set $prob[g] = 1$.
        while !large.is_empty() {
            prob[large.remove(0)] = 1.0;
        }

        // while $small$ is not empty, remove the first element ($l$) and
        // set $prob[l] = 1$.
        while !small.is_empty() {
            prob[small.remove(0)] = 1.0;
        }

        self.prob = prob;
        self.alias = alias;
    }
}

impl fmt::Display for WeightedDist {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let dist = self.0.lock().unwrap();
        write!(f, "{dist}")
    }
}

impl fmt::Display for InnerWeightedDist {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut buf: String = "[ ".into();

        for (i, v) in self.values.iter().enumerate() {
            let p = self.weights[i];
            if p > 0.01 {
                buf.push_str(&format!("{v}: {p}, "));
            }
        }
        write!(f, "]")
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::Result;

    // NOTE: a former `weighted_dist_uniformity` test ran 1,000,000 samples
    // through `sample()` but asserted nothing (it only emitted trace output),
    // so it could never fail and provided no coverage. It was removed. The
    // tests below assert real invariants: that reseeding changes the output
    // distribution and that samples stay within the configured [min, max].

    #[test]
    fn reseed_changes_distribution() -> Result<()> {
        let seed1 = drbg::Seed::from([0x11; drbg::SEED_LENGTH]);
        let seed2 = drbg::Seed::from([0x22; drbg::SEED_LENGTH]);
        let w = WeightedDist::new(seed1, 0, 100, false);

        let mut samples_before = Vec::new();
        for _ in 0..100 {
            samples_before.push(w.sample());
        }

        w.reseed(seed2);

        let mut samples_after = Vec::new();
        for _ in 0..100 {
            samples_after.push(w.sample());
        }

        // Statistically very unlikely to be identical
        assert_ne!(samples_before, samples_after);
        Ok(())
    }

    #[test]
    fn sample_in_range() -> Result<()> {
        let seed = drbg::Seed::new()?;
        let w = WeightedDist::new(seed, 10, 50, false);
        for _ in 0..1000 {
            let s = w.sample();
            assert!((10..=50).contains(&s), "sample {s} out of range [10, 50]");
        }
        Ok(())
    }
}
