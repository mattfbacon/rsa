/*
rsa: a simple implementation of RSA encryption and decryption, as
well as key generation with small primes (8 bits).
Copyright (C) 2021  Matt Fellenz <mattf53190@gmail.com>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
*/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <limits.h>
#include <math.h>
#include "util.h"
#include "rsa.h"
#include "main.h"

static const unsigned short low_primes[] = {
	3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,
	97,101,103,107,109,113,127,131,137,139,149,151,157,163,167,173,
	179,181,191,193,197,199,211,223,227,229,233,239,241,251,257,263,
	269,271,277,281,283,293,307,311,313,317,331,337,347,349,353,359,
	367,373,379,383,389,397,401,409,419,421,431,433,439,443,449,457,
	461,463,467,479,487,491,499,503,509,521,523,541,547,557,563,569,
	571,577,587,593,599,601,607,613,617,619,631,641,643,647,653,659,
	661,673,677,683,691,701,709,719,727,733,739,743,751,757,761,769,
	773,787,797,809,811,821,823,827,829,839,853,857,859,863,877,881,
	883,887,907,911,919,929,937,941,947,953,967,971,977,983,991,997
};

static const unsigned char num_low_primes = 167;

unsigned int get_random(const unsigned int max) {
	const unsigned int limit = UINT_MAX - (UINT_MAX % max);
	unsigned int r;

	FILE* f = fopen("/dev/random", "r");

	do {
		fread(&r, sizeof(r), 1, f);
	} while(r >= limit);

	fclose(f);

	verbose_logf("got random %u (mod %u for final result)\n", r, max);

	return r % max;
}

unsigned int gcd(unsigned int a, unsigned int b) {
	verbose_logf("getting gcd of %u and %u\n", a, b);
	while (b != 0) {
		unsigned int temp;
		temp = a;
		a = b;
		b = temp % b;
	}
	return a;
}

unsigned int multiplicative_inverse(unsigned int a, unsigned int b) {
	verbose_logf("getting multiplicative inverse of %u and %u\n", a, b);
	#pragma GCC diagnostic push
	#pragma GCC diagnostic ignored "-Wsign-conversion"
	unsigned int x = 0, y = 1, oa = a, ob = b;
	int lx = 1, ly = 0;
	while (b != 0) {
		unsigned int temp;
		const unsigned int q = a / b; // floor div
		temp = a;
		a = b;
		b = temp % b;
		temp = x;
		x = lx - (q * x);
		lx = temp;
		temp = y;
		y = ly - (q * y);
		ly = temp;
	}
	if (lx < 0) lx += ob;
	if (ly < 0) ly += oa;
	return lx; // where ia + jb = gdb(a, b), return i.
	#pragma GCC diagnostic pop
}

bool rabin_miller_check(unsigned int base, const unsigned int limit, const unsigned int exp, const unsigned int modulus) {
	verbose_logf("rabin miller check with base %u, limit %u, exponent %u, and modulus %u\n", base, limit, exp, modulus);
	base = mod_pow(base, exp, modulus);
	if (base == 1) return true;
	for (unsigned int i = 1; i < limit - 1; i++) {
		if (base == modulus - 1) return true;
		base = mod_pow(base, 2, modulus);
	}
	return base == modulus - 1;
}

bool rabin_miller(const unsigned int n) {
	verbose_logf("rabin miller with %u\n", n);
	if (n == 2) return true;
	if (n % 2 == 0) return false;

	unsigned int limit = 0;
	unsigned int exp = n - 1;

	while (exp % 2 == 0) {
		exp /= 2;
		limit += 1;
	}

	for (unsigned int i = 1; i < RABIN_MILLER_TRIES; i++) {
		verbose_logf("  iterate: ");
		const unsigned int base = randrange(2, n - 1);
		if(!rabin_miller_check(base, limit, exp, n)) return false;
	}
	return true;
}

bool is_prime(const unsigned int n) {
	// will always properly identify composites, but sometimes considers primes composites. Fine for our use case.
	verbose_logf("checking if %u is prime\n", n);
	if (n >= 3 && n % 2 == 1) {
		for (int i = 0; i < num_low_primes; i++) {
			unsigned int p;
			p = low_primes[i];
			if (n == p) return true;
			if (n % p == 0) return false;
		}
		return rabin_miller(n);
	}
	return false;
}

unsigned int mod_pow(unsigned long base, unsigned int exp, const unsigned int mod) {
	verbose_logf("modular exponentiation: %lu^%u mod %u\n", base, exp, mod);
	if (mod == 1) return 0;
	unsigned long result = 1;
	base = base % mod;
	while (exp > 0) {
		if (exp % 2 == 1) {
			result = (result * base) % mod;
		}
		exp /= 2;
		base = (base * base) % mod;
	}
	return (unsigned int)result;
}

void print_generic_usage_with_complaint_and_readback_short_option(immutable_string_t complaint, const char option_name) {
	fputs("rsa: ", stderr);
	fputs(complaint, stderr);
	fputs(" '-", stderr);
	putc(option_name, stderr);
	fputs("'\n", stderr);
	print_generic_usage(true);
}
void print_generic_usage_with_complaint_and_readback_string(immutable_string_t complaint, immutable_string_t content) {
	fputs("rsa: ", stderr);
	fputs(complaint, stderr);
	fputs(" '", stderr);
	fputs(content, stderr);
	fputs("'\n", stderr);
	print_generic_usage(true);
}
void print_generic_usage_with_complaint(immutable_string_t complaint) {
	fputs("rsa: ", stderr);
	fputs(complaint, stderr);
	putc('\n', stderr);
	print_generic_usage(true);
}
void print_generic_usage(const bool in_error) {
	fputs(
		"COMMANDS:\n"
		"  encrypt <key> <modulus> <plaintext>\n"
		"  decrypt <key> <modulus> <ciphertext>\n"
		"  keygen\n"
		"if plaintext or ciphertext is '-', read from stdin.\n"
		"OPTIONS:\n"
		"  -v, --verbose: print detailed progress info along with output.\n"
		"  -b, --brief: print only output in a human-friendy format (default).\n"
		"  -q, --quiet: print only output in a consistent, machine-readable format.\n"
		"  -V, --version: print version info and exit.\n"
		"  -h, --help, --usage: print usage and exit.\n"
		"  -f<arg>, --format <arg>: the format of plaintext, either `chars` (default, raw characters) or `numbers` (unsigned ints). The ciphertext is always in numbers format due to technical restrictions.\n"
		"  -d<arg>, --delimiter <arg>: the delimiter between the numbers when in numbers mode. A space by default. Cannot include digits.\n"
		"if multiple of -v, -b, and/or -q are provided, the last takes precedence. Same with multiple formats or delimiters.\n",
		in_error ? stderr : stdout
	);
	exit(in_error ? EXIT_USAGE_ERROR : EXIT_SUCCESS);
}
void print_specific_usage(const enum e_command command, const bool in_error) {
	switch(command) {
		case ENCRYPT:
			fputs(
				"HELP WITH encrypt:\n"
				"  encrypt <key> <modulus> <plaintext>\n"
				"arguments:\n"
				"  key: an unsigned integer representing the public/private key as generated by the keygen command\n"
				"  modulus: an unsigned integer representing the modulus as generated by the keygen command\n"
				"  plaintext: the message you want to encrypt. please provide as one argument by using quotes if the message contains spaces\n"
				"behavior:\n"
				"  if plaintext is '-', the message is read from stdin. If the message is provided from stdin, no encrypted trailing newline is added.\n"
				"  in both cases (reading from stdin and from the argument) an actual trailing newline is added per the POSIX definition of a line.\n"
				"  the output is unsigned integers separated by the delimiter specified with -d or a space by default.\n",
				in_error ? stderr : stdout
			); break;
		case DECRYPT:
			fputs(
				"HELP WITH decrypt:\n"
				"  decrypt <key> <modulus> <ciphertext>\n"
				"arguments:\n"
				"  key: an unsigned integer representing the public/private key as generated by the keygen command. make sure it is the paired key to the one used to encrypt\n"
				"  modulus: an unsigned integer representing the modulus as generated by the keygen command\n"
				"  ciphertext: the message you want to decrypt, in the format of unsigned integers separated by spaces or a custom delimiter specified by -d. please provide as one argument by using quotes\n"
				"behavior:\n"
				"  if ciphertext is '-', the message is read from stdin.\n"
				"  in both cases (reading from stdin and from the argument) no actual trailing newline is added since it should have been encrypted along with the message.\n",
				in_error ? stderr : stdout
			); break;
		case KEYGEN:
			fputs(
				"HELP WITH keygen:\n"
				"  keygen\n"
				"arguments:\n"
				"  (none)\n"
				"behavior:\n"
				"  the output is a public/private keypair and a modulus.\n"
				"  in quiet mode (-q), the numbers are output without labels, in public private modulus order (same as default).",
				in_error ? stderr : stdout
			); break;
	}
	exit(in_error ? EXIT_USAGE_ERROR : EXIT_SUCCESS);
}
bool streq(immutable_string_t str1, immutable_string_t str2) {
	return strcmp(str1, str2) == 0;
}
bool strstartswith(const char* str, const char* pre) {
	for(; *pre != '\0'; pre += sizeof(char), str += sizeof(char)) { // prefix still has chars
		if(*pre != *str) return false;
	}
	return true;
}
bool str_to_uint_safe(immutable_string_t str, unsigned int* const out) {
	char* nonnumber_chars;
	const unsigned long result = strtoul(str, &nonnumber_chars, 0);
	if (result > UINT_MAX) return false; // number won't fit in uint.
	if (strlen(nonnumber_chars) != 0) return false; // if there are extraneous characters, the number was invalid.
	*out = (unsigned int)result;
	return true;
}

void str_scanf_escape(const char* str, char* out) { // out should be 2x strlen of str, to be safe
	for (size_t i = 0; *str != '\0'; str += sizeof(char), i++) {
		out[i] = *str;
		if (*str == '%') out[++i] = '%';
	}
}
