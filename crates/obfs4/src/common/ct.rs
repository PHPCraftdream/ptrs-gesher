//! Constant-time utilities.
use subtle::{Choice, ConstantTimeEq};

/// Convert a boolean into a Choice.
///
/// This isn't necessarily a good idea or constant-time.
pub(crate) fn bool_to_choice(v: bool) -> Choice {
    Choice::from(u8::from(v))
}

/// Return true if two slices are equal.  Performs its operation in constant
/// time, but returns a bool instead of a subtle::Choice.
#[allow(unused)]
pub(crate) fn bytes_eq(a: &[u8], b: &[u8]) -> bool {
    let choice = a.ct_eq(b);
    choice.unwrap_u8() == 1
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bytes_eq_equal() {
        assert!(bytes_eq(b"hello", b"hello"));
    }

    #[test]
    fn bytes_eq_unequal_same_len() {
        assert!(!bytes_eq(b"hello", b"world"));
    }

    #[test]
    fn bytes_eq_different_len() {
        assert!(!bytes_eq(b"hello", b"hi"));
    }

    #[test]
    fn bytes_eq_empty() {
        assert!(bytes_eq(b"", b""));
    }

    #[test]
    fn bytes_eq_one_empty() {
        assert!(!bytes_eq(b"a", b""));
        assert!(!bytes_eq(b"", b"a"));
    }

    #[test]
    fn bytes_eq_single_byte_diff() {
        assert!(!bytes_eq(&[0x00], &[0x01]));
        assert!(bytes_eq(&[0xff], &[0xff]));
    }
}
