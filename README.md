# Aleo Secure Key generator

Want an Aleo address with a specific suffix? Now you can.
Output the results as encrypted by the passwords

## Usage

`cargo run --release -- "suffix" <number_of_address>`

for example:

`cargo run --release -- dem0x 1`

## Considerations

 * This code has not be audited at all. You should review the source youself.
 * Bech32 encoding is used and the suffix is not checked so it'll spin forever if you try to find a suffix with invalid Bech32 characters ie "b"
 * Number of guesses and some statistical information are printed in addition to the found private keys
 * It'll require on average 32^(number_characters) => `dem0x` takes ~33M guesses or about 10 min on a Macbook Pro.