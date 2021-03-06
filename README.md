# RSA Implementation

A simple implementation of RSA encryption and decryption, as well as key generation with small primes (8 bits).

Note: before you get mad at me, I know this is not actually RSA. It was just a way to learn C.

## Building/Installation

Due to the use of `/dev/urandom`, **this will only run on Linux!** A port to other operating systems is trivial and thus is left as an exercise to the user (or just run Linux).

Just run `make` in the repository's root directory to get a binary at `bin/rsa`. No unusual binaries or libraries are required.

While this binary could be installed, it is not recommended since it has such a generic name.

## Usage

### Commands

 - `encrypt <key> <modulus> <plaintext>`
 - `decrypt <key> <modulus> <ciphertext>`
 - `keygen`

If plaintext or ciphertext is `-`, read from stdin.

### Options

 - `-v`, `--verbose`: Print detailed progress info along with output.
 - `-b`, `--brief`: Print only output in a human-friendy format (default).
 - `-q`, `--quiet`: Print only output in a consistent, machine-readable format.
 - `-V`, `--version`: Print version info and exit.
 - `-h`, `--help`, `--usage`: Print usage and exit.
 - `-f<arg>`, `--format <arg>`: The format of plaintext, either `chars` (default, raw characters) or `numbers` (unsigned ints). The ciphertext is always in numbers format due to technical restrictions.
 - `-d<arg>`, `--delimiter <arg>`: The delimiter between the numbers when in numbers mode. A space by default. Cannot include digits.

If multiple of `-v`, `-b`, and/or `-q` are provided, the last takes precedence. Same with multiple formats or delimiters.

## Detailed Usage

### `encrypt <key> <modulus> <plaintext>`

#### Arguments

 - `key`: An unsigned integer representing the public/private key as generated by the `keygen` command.
 - `modulus`: An unsigned integer representing the modulus as generated by the `keygen` command.
 - `plaintext`: Rhe message you want to encrypt. Please provide as one argument by using quotes if the message contains spaces.

#### Behavior

If plaintext is `-`, the message is read from stdin. If the message is provided from stdin, no encrypted trailing newline is added.    
In both cases (reading from stdin and from the argument) an actual trailing newline is added per the POSIX definition of a line.    
The output is unsigned integers separated by the delimiter specified with `-d` or a space by default.

### `decrypt <key> <modulus> <ciphertext>`

#### Arguments

 - `key`: An unsigned integer representing the public/private key as generated by the `keygen` command. Make sure it is the paired key to the one used to encrypt.
 - `modulus`: An unsigned integer representing the modulus as generated by the `keygen` command.
 - `ciphertext`: The message you want to decrypt, in the format of unsigned integers separated by spaces or a custom delimiter specified by `-d`. Please provide as one argument by using quotes.

#### Behavior

If ciphertext is `-`, the message is read from stdin.    
In both cases (reading from stdin and from the argument) no actual trailing newline is added since it should have been encrypted along with the message.

### `keygen`

#### Arguments

No arguments.

#### Behavior

The output is a public/private keypair and a modulus.    
In quiet mode (`-q`), the numbers are output without labels, in public private modulus order (same as default).

## Contributing

Pull requests are welcome and appreciated. There may be issues open, in which case the first priority is to resolve them, before introducing new features.

## License

[GPL v3.0 only](https://choosealicense.com/licenses/gpl-3.0/)
