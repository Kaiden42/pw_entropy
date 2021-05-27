//! # PW-Entropy
//!
//! This crate calculates the entropy of a password. The entropy is the amount of
//! brute-force guesses an attacker needs to crack a password. It is calculated with
//! `log_2(base ^ length)` where base is the sum of the character groups the password
//! contains at least one character of.
//!
//! ## Example
//! ```rust
//! use pw_entropy::PasswordInfo;
//!
//! let password = "ThisIsASecret";
//! let entropy = PasswordInfo::for_password(password).get_entropy();
//! ```
#![deny(missing_docs)]
#![deny(missing_debug_implementations)]
#![deny(unused_results)]
#![forbid(unsafe_code)]
#![warn(
    clippy::pedantic,
    clippy::nursery,

    // Restriction lints
    clippy::clone_on_ref_ptr,
    clippy::create_dir,
    clippy::dbg_macro,
    clippy::decimal_literal_representation,
    clippy::exit,
    clippy::float_cmp_const,
    clippy::get_unwrap,
    clippy::let_underscore_must_use,
    clippy::map_err_ignore,
    clippy::mem_forget,
    clippy::missing_docs_in_private_items,
    clippy::multiple_inherent_impl,
    clippy::panic,
    clippy::panic_in_result_fn,
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::rest_pat_in_fully_bound_structs,
    clippy::str_to_string,
    clippy::string_to_string,
    clippy::todo,
    clippy::unimplemented,
    clippy::unneeded_field_pattern,
    clippy::unwrap_in_result,
    clippy::unwrap_used,
    clippy::use_debug,
)]
#![allow(
    clippy::suboptimal_flops,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::module_name_repetitions
)]

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

/// The list of the replace characters.
pub const REPLACE_CHARS: &str = "!@$&*";
/// The list of the separator characters.
pub const SEPARATOR_CHARS: &str = "_-., ";
/// The list of the special characters that are neither a replace nor separator character.
pub const OTHER_SPECIAL_CHARS: &str = "\"#%'()+/:;<=>?[\\]^{|}~";
/// The list of lower characters.
pub const LOWER_CHARS: &str = "abcdefghijklmnopqrstuvwxyz";
/// The list of upper characters.
pub const UPPER_CHARS: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
/// The list of digits.
pub const DIGIT_CHARS: &str = "0123456789";

/// The info about a password to calculate the password's entropy.
#[derive(Debug)]
#[allow(clippy::struct_excessive_bools)]
pub struct PasswordInfo {
    /// The stripped length of the password.
    length: usize,
    /// The calculated base of the password.
    base: u16,
    /// The password contains at least one replace character.
    has_replace: bool,
    /// The password contains at least one separator character.
    has_seperator: bool,
    /// The password contains at least one spacial character.
    has_other_special: bool,
    /// The password contains at least one lower character.
    has_lower: bool,
    /// The password contains at least one upper character.
    has_upper: bool,
    /// The password contains at least one digit.
    has_digit: bool,
}

impl PasswordInfo {
    /// Calculates a new [`PasswordInfo`](PasswordInfo) for the given password.
    ///
    /// It will create a local copy of the password to remove common sequences,
    /// duplicate characters and a possible palindrome. All of these are bad for
    /// a good password.
    ///
    /// If overwriting of the local copy with zeros is needed, after the
    /// calculation is done, activate the feature `zeroize`.
    #[must_use]
    pub fn for_password(password: &str) -> Self {
        //let password = password.to_owned();
        let mut password: Vec<char> = password.chars().collect();
        remove_palindrome(&mut password);
        remove_common_sequences(&mut password);
        remove_repeating_characters(&mut password);

        let has_replace = REPLACE_CHARS.chars().any(|c| password.contains(&c));
        let has_seperator = SEPARATOR_CHARS.chars().any(|c| password.contains(&c));
        let has_other_special = OTHER_SPECIAL_CHARS.chars().any(|c| password.contains(&c));
        let has_lower = LOWER_CHARS.chars().any(|c| password.contains(&c));
        let has_upper = UPPER_CHARS.chars().any(|c| password.contains(&c));
        let has_digits = DIGIT_CHARS.chars().any(|c| password.contains(&c));

        let length = password.len();

        #[cfg(feature = "zeroize")]
        password.zeroize();

        let mut base = 0;

        if has_replace {
            base += REPLACE_CHARS.len();
        }
        if has_seperator {
            base += SEPARATOR_CHARS.len();
        }
        if has_other_special {
            base += OTHER_SPECIAL_CHARS.len();
        }
        if has_lower {
            base += LOWER_CHARS.len();
        }
        if has_upper {
            base += UPPER_CHARS.len();
        }
        if has_digits {
            base += DIGIT_CHARS.len();
        }

        Self {
            length,
            base: base as u16,
            has_replace,
            has_seperator,
            has_other_special,
            has_lower,
            has_upper,
            has_digit: has_digits,
        }
    }

    /// The length of the password after removing common sequences, duplicate
    /// characters and a possible palindrome.
    #[must_use]
    pub const fn length(&self) -> usize {
        self.length
    }

    /// The calculated base of the password
    #[must_use]
    pub const fn base(&self) -> u16 {
        self.base
    }

    /// True, if the password contains replace characters.
    #[must_use]
    pub const fn has_replace_character(&self) -> bool {
        self.has_replace
    }

    /// True, if the password contains seperator characters.
    #[must_use]
    pub const fn has_seperator_character(&self) -> bool {
        self.has_seperator
    }

    /// True, if the password contains other special characters that are neither
    /// replace nor seperator characters.
    #[must_use]
    pub const fn has_other_special_character(&self) -> bool {
        self.has_other_special
    }

    /// True, if the password contains at least one lower character.
    #[must_use]
    pub const fn has_lower_character(&self) -> bool {
        self.has_lower
    }

    /// True, if the password contains at least one upper character.
    #[must_use]
    pub const fn has_upper_character(&self) -> bool {
        self.has_upper
    }

    /// True, if the password contains at least one digit.
    #[must_use]
    pub const fn has_digit(&self) -> bool {
        self.has_digit
    }

    /// Calculates the entropy of the password based on: `log_2(base ^ length)`.
    #[must_use]
    pub fn get_entropy(&self) -> f64 {
        log_power(f64::from(self.base), self.length, 2.0)
    }
}

/// Removes repeating characters from the password in place.
fn remove_repeating_characters(password: &mut Vec<char>) {
    password.dedup()
}

/// Removes the palindrome if it exists. If the password is a palindrome the
/// half of the palindrome will be removed in place.
fn remove_palindrome(password: &mut Vec<char>) {
    let half = password.len() / 2 + password.len() % 2;

    let forwards = password.iter().take(half).map(|c| c.to_lowercase());

    let backwards = password.iter().rev().take(half).map(|c| c.to_lowercase());

    let is_palindrome = forwards.zip(backwards).all(|(f, b)| f.eq(b));

    if is_palindrome {
        password.truncate(half);
    }
}

/// Common password sequences to remove
static COMMON_SEQUENCES: &[&str] = &[
    "asdf",
    "jkl;",
    ";lkj",
    "fdsa",
    "asdfghjkl",
    "asdf ;lkj",
    "0123456789",
    "qwertyuiop",
    "qwerty",
    "zxcvbnm",
    "abcdefghijklmnopqrstuvwxyz",
    "password1",
    "password!",
    "password",
    "Password",
    "assword",
    "picture1",
    "Picture1",
    "picture",
    "Picture",
    "asdf",
    "rty567",
    "senha",
    "abc123",
    "Million2",
    "000000",
    "1234",
    "iloveyou",
    "aaron431",
    "qqww1122",
    "123123",
];

/// Removes common password sequences from the given password in place.
fn remove_common_sequences(password: &mut Vec<char>) {
    COMMON_SEQUENCES
        .iter()
        .map(|s| s.chars().collect::<Vec<char>>())
        .for_each(|sequence| {
            let len = sequence.len();

            // Each sequence could occur multiple times.
            // TODO: ignore case
            while let Some(position) = password.windows(len).position(|w| w.eq(&sequence)) {
                drop(password.drain(position..(position + len)))
            }
        });
}

/// Calculates `log_b(e^p)` where b is the base of the logarithm, e is the base
/// of the exponent and p is the power.
/// The calculation is done in logspace for each multiplication step to reduce
/// memory usage ( `log_b(M * N) = log_b(M) + log_b(N)` ).
fn log_power(exp_base: f64, power: usize, log_base: f64) -> f64 {
    std::iter::repeat(exp_base.log(log_base))
        .take(power as usize)
        .sum()
}

#[cfg(test)]
mod tests {
    use crate::{
        log_power, remove_common_sequences, remove_palindrome, remove_repeating_characters,
        PasswordInfo, DIGIT_CHARS, LOWER_CHARS, OTHER_SPECIAL_CHARS, REPLACE_CHARS,
        SEPARATOR_CHARS, UPPER_CHARS,
    };
    const ERROR_MARGIN: f64 = f64::EPSILON;

    #[test]
    fn test_entropy() {
        // Password only uses lowercase => base = 26 with length of 7 characters
        // https://www.wolframalpha.com/input/?i=log2%2826%5E7%29
        let password = "letmein";
        let expected = 7.0 * 26.0_f64.log10() / 2.0_f64.log10();
        assert!((expected - PasswordInfo::for_password(password).get_entropy()) < ERROR_MARGIN);

        // Password is empty => entropy = 0.0
        let password = "";
        let expected = 0.0;
        assert!((expected - PasswordInfo::for_password(password).get_entropy()) < ERROR_MARGIN);

        // Password uses upper- and lowercase => base = 2*26 with length of 7 characters
        // https://www.wolframalpha.com/input/?i=log2%28%282*26%29%5E7%29
        let password = "LetMeIn";
        let expected = 7.0 * (2.0 * 26.0_f64).log10() / 2.0_f64.log10();
        assert!((expected - PasswordInfo::for_password(password).get_entropy()) < ERROR_MARGIN);

        // Password contains one character for each group with length of 6
        let password = "!_\"aA0";
        let expected = 6.0
            * ((REPLACE_CHARS.len()
                + SEPARATOR_CHARS.len()
                + OTHER_SPECIAL_CHARS.len()
                + LOWER_CHARS.len()
                + UPPER_CHARS.len()
                + DIGIT_CHARS.len()) as f64)
                .log10()
            / 2.0_f64.log10();
        assert!((expected - PasswordInfo::for_password(password).get_entropy()) < ERROR_MARGIN);
    }

    #[test]
    fn test_log_power() {
        // https://www.wolframalpha.com/input/?i=log2%2826%5E7%29
        let expected = 7.0 * 26.0_f64.log10() / 2.0_f64.log10();
        assert!((expected - log_power(26.0, 7, 2.0)).abs() < ERROR_MARGIN);

        // https://www.wolframalpha.com/input/?i=log2%280%5E42%29
        assert!(log_power(0.0, 42, 2.0).is_infinite());

        // https://www.wolframalpha.com/input/?i=log2%285%5E0%29
        let expected = 0.0;
        assert!((expected - log_power(5.0, 0, 2.0)) < ERROR_MARGIN);
    }

    #[test]
    fn test_remove_common_sequences() {
        let mut password: Vec<char> = "password".chars().collect();
        remove_common_sequences(&mut password);
        let expected: Vec<char> = Vec::new();
        assert_eq!(expected, password);

        let mut password: Vec<char> = "asdf|password|asdf|qwerty".chars().collect();
        remove_common_sequences(&mut password);
        let expected: Vec<char> = "|||".chars().collect();
        assert_eq!(expected, password);

        let mut password: Vec<char> = "1234ThisIsUntouched!asdf".chars().collect();
        remove_common_sequences(&mut password);
        let expected: Vec<char> = "ThisIsUntouched!".chars().collect();
        assert_eq!(expected, password);
    }

    #[test]
    fn test_remove_duplicates() {
        let mut password: Vec<char> = "aabbccddeeff".chars().collect();
        remove_repeating_characters(&mut password);
        let expected: Vec<char> = "abcdef".chars().collect();
        assert_eq!(expected, password);

        let mut password: Vec<char> = "abba".chars().collect();
        remove_repeating_characters(&mut password);
        let expected: Vec<char> = "aba".chars().collect();
        assert_eq!(expected, password);

        let mut password: Vec<char> = "aabbbccccdddddeeeeeefffffff".chars().collect();
        remove_repeating_characters(&mut password);
        let expected: Vec<char> = "abcdef".chars().collect();
        assert_eq!(expected, password);
    }

    #[test]
    fn test_remove_palindrome() {
        let mut password: Vec<char> = "abba".chars().collect();
        remove_palindrome(&mut password);
        let expected: Vec<char> = "ab".chars().collect();
        assert_eq!(expected, password);

        let mut password: Vec<char> = "Abcdedcba".chars().collect();
        remove_palindrome(&mut password);
        let expected: Vec<char> = "Abcde".chars().collect();
        assert_eq!(expected, password);
    }
}
