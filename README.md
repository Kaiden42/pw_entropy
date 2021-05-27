# PW-Entropy

This crate was inspired by the [CHBS Password Strength Checker](https://github.com/induane/chbs), which itself was inspired by the [go-password-validator](https://github.com/wagslane/go-password-validator). The difference to CHBS is that this crate is focussed on performance and minimal required memory allocation.

Many password checkers are wrong. It should not matter if a password must contain at least one upper, lower, digit and special character if it is long enough. What matters is the *entropy* of the password. The *entropy* refers to the number of brute-force guesses an attacker needs to crack the password. This will be measured in bits (the exponent `n` in `2^n`). You can read more about it here: [How To Correctly Validate Passwords](https://qvault.io/golang/how-to-correctly-validate-passwords-most-websites-do-it-wrong/).

To calculate the entropy, the CHBS Password Strength Checker and therefore this crate are removing palindromes, repeating characters and common sequences from the password before calculating the passwords entropy. All of these actions are only shrinking the size of the password. Therefore no additional memory is needed than exactly one local copy of the password. Everything is done in-place. If zeroing the local copy of the password is necessary, after the calculation is done, activate the feature `zeroize`.

**How to use:**
```Rust
use pw_entropy::PasswordInfo;

let password = "ThisIsASecret";
let entropy = PasswordInfo::for_password(password).get_entropy();
println!("Bits: {}", entropy);

>>> Bits: 74.1057163358342
```

## How does it work?

The entropy of a password is calculated by `log_2(base ^ length)`, where `base` is the amount of characters the password could contain.

The base is a sum of the following groups, if the password contains at least one character of the group:
- 26 lowercase letters
- 26 uppercase letters
- 10 digits
- 5 replacement characters (`!@$&*`)
- 5 separator characters (`_-., `)
- 22 other special characters (`"#%'()+/:;<=>?[\]^{|}~`)

Repeating characters like `aaaaaaaaa` will only count as one `a`. and the following common sequences will be entirely removed:

- `asdf`
- `jkl;`
- `;lkj`
- `fdsa`
- `asdfghjkl`
- `asdf ;lkj`
- `0123456789`
- `qwertyuiop`
- `qwerty`
- `zxcvbnm`
- `abcdefghijklmnopqrstuvwxyz`
- `password1`
- `password!`
- `password`
- `Password`
- `assword`
- `picture1`
- `Picture1`
- `picture`
- `Picture`
- `asdf`
- `rty567`
- `senha`
- `abc123`
- `Million2`
- `000000`
- `1234`
- `iloveyou`
- `aaron431`
- `qqww1122`
- `123123`

If the password is a palindrome like `Lagerregal` or `abcdcba` the password will be cut in half.

**For example:** The password `Password?` contains at least one character of the categories *uppercase (26)*, *lowercase (26)* and *digit (10)*. This sums up to a base of `26+26+10 = 62` and the length of the password is `9`. The entropy of the password would normally be `log_2(62 ^ 9) = 53.587766793481876 bits`. But since `Password` is a common sequence, the sequence will be removed (only the question mark is left), so the actual entropy this crates calculates is only `log_2(22 ^ 1) = 4.459431618637297 bits`.

## What is a good minimum value?

That depends. Take a look at this [graphic](https://camo.githubusercontent.com/db2b0045f11eb8e5025da3e015fc3221d29aa37fd7a2e9d018a7584f99cbb5e2/68747470733a2f2f65787465726e616c2d707265766965772e726564642e69742f7268644144495a59584a4d324678714e6636554f467155356172305658336661794c46704b73704e3875492e706e673f6175746f3d7765627026733d39633134326562623337656434633339666236323638633165346636646335323964636234323832) to create an overview for yourself.