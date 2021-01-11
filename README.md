# RSA Implementation

A simple implementation of RSA encryption and decryption, as well as key generation with small primes (8 bits).

## Building/Installation

Due to the use of `/dev/urandom`, **this will only run on Linux!** A port to other operating systems is trivial and thus is left as an exercise to the user (or just run Linux).

Just run `make` in the repository's root directory to get a binary at `bin/rsa`. No unusual binaries or libraries are required.

While this binary could be installed, it is not recommended since it has such a generic name.

## Usage

Basic usage is printed if the program is run with no arguments.

The three command verbs are `keygen`, `encrypt`, and `decrypt`.

### `keygen`
`keygen` takes no arguments. It outputs a public/private keypair as well as the modulus, as expected by `encrypt` and `decrypt`.

```
$ ./rsa keygen
public key: 1835
private key: 11159
modulus: 29893
```

### `encrypt`

`encrypt` takes three arguments: the key, the modulus, and the message. The key and modulus are unsigned integers, while the message is a string. If the message is `-`, read from stdin.

When encrypting from an argument (i.e., not from stdin), a newline will be appended to the end of the plaintext before encrypting. In both modes, an actual trailing newline is included with the output as per [the UNIX definition of a line](https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap03.html#tag_03_206).

The format for the resulting ciphertext is unsigned integers divided by spaces. If you'd like another delimiter, pipe the output into `tr`. The only output other than spaces is numerals from zero to nine, and the trailing newline.

```
$ ./rsa encrypt 1835 29893 abc
25371 28573 13701 27881
```

(Encrypted newline and trailing newline included)

```
$ echo -n 'abc' | ./rsa encrypt 1835 29893 -
25371 28573 13701
```

(Only trailing newline included)

### `decrypt`

`decrypt` takes the same arguments as `encrypt` (key, modulus, message), except the message is expected to be a list of unsigned integers separated by spaces. For the message, quote the argument in your shell, or otherwise only the first number will be processed.

As with `encrypt`, if in place of the message `-` is provided, read from stdin.

This command outputs the ciphertext exactly as it was encrypted: no trailing newline is added.

```
$ ./rsa decrypt 11159 29893 '25371 28573 13701 27881'
abc
```

As an example of what **not to do**, not quoting the argument will result in only the first number being processed (the enter symbol indicates no trailing newline):

```
$ ./rsa decrypt 11159 29893 25371 28573 13701 27881
a⏎
```

## Contributing

Pull requests are welcome and appreciated. There may be issues open, in which case the first priority is to resolve them, before introducing new features.

## License

[GPL v3.0 only](https://choosealicense.com/licenses/gpl-3.0/)
