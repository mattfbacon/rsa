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

static unsigned short low_primes[] = {
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

static unsigned char num_low_primes = 167;

unsigned int get_random(unsigned int max) {
	const unsigned int limit = UINT_MAX - (UINT_MAX % max);
	unsigned int r;

	FILE *f;
	f = fopen("/dev/random", "r");

	do {
		fread(&r, sizeof(r), 1, f);
	} while(r >= limit);

	fclose(f);

	return r % max;
}

unsigned int gcd(unsigned int a, unsigned int b) {
	unsigned int temp;
	while (b != 0) {
		temp = a;
		a = b;
		b = temp % b;
	}
	return a;
}

unsigned int multiplicative_inverse(unsigned int a, unsigned int b) {
	#pragma GCC diagnostic push
	#pragma GCC diagnostic ignored "-Wsign-conversion"
	unsigned int x = 0, y = 1, oa = a, ob = b, q;
	int lx = 1, ly = 0;
	unsigned int temp;
	while (b != 0) {
		q = a / b; // floor div
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

bool rabin_miller_check(unsigned int base, unsigned int limit, unsigned int exp, unsigned int modulus) {
	base = mod_pow(base, exp, modulus);
	if (base == 1) return true;
	for (unsigned int i = 1; i < limit - 1; i++) {
		if (base == modulus - 1) return true;
		base = mod_pow(base, 2, modulus);
	}
	return base == modulus - 1;
}

bool rabin_miller(unsigned int n) {
	if (n == 2) return true;
	if (n % 2 == 0) return false;

	unsigned int limit = 0;
	unsigned int exp = n - 1;
	unsigned int base;

	while (exp % 2 == 0) {
		exp >>= 1;
		limit += 1;
	}

	for (unsigned int i = 1; i < RABIN_MILLER_TRIES; i++) {
		base = randrange(2, n - 1);
		if(!rabin_miller_check(base, limit, exp, n)) return false;
	}
	return true;
}

bool is_prime(unsigned int n) {
	// will always properly identify composites, but sometimes considers primes composites. Fine for our use case.
	if (n >= 3) {
		if (n % 2 == 1) {
			unsigned int p;
			for (unsigned char i = 0; i < num_low_primes; i++) {
				p = low_primes[i];
				if (n == p) return true;
				if (n % p == 0) return false;
			}
			return rabin_miller(n);
		}
	}
	return false;
}

unsigned int mod_pow(unsigned long base, unsigned int exp, unsigned int mod) {
	if (mod == 1) return 0;
	unsigned long result = 1;
	base = base % mod;
	while (exp > 0) {
		if (exp % 2 == 1) {
			result = (result * base) % mod;
		}
		exp = exp >> 1;
		base = (base*base) % mod;
	}
	return (unsigned int)result;
}

void print_generic_usage_with_complaint_and_readback_short_option(char* complaint, char option_name) {
	fputs("rsa: ", stdout);
	fputs(complaint, stdout);
	fputs(" '-", stdout);
	putchar(option_name);
	puts("'");
	print_generic_usage();
}
void print_generic_usage_with_complaint_and_readback_string(char* complaint, char* content) {
	fputs("rsa: ", stdout);
	fputs(complaint, stdout);
	fputs(" '", stdout);
	fputs(content, stdout);
	puts("'");
	print_generic_usage();
}
void print_generic_usage_with_complaint(char* complaint) {
	fputs("rsa: ", stdout);
	puts(complaint);
	print_generic_usage();
}
void print_generic_usage() {
	printf("Usage:\n  encrypt <key> <modulo> <plaintext>\n  decrypt <key> <modulo> <ciphertext>\n  keygen\nIf plaintext or ciphertext is \"-\", read from stdin.\n");
	exit(EXIT_USAGE_ERROR);
}
bool streq(char* str1, char* str2) {
	return strcmp(str1, str2) == 0;
}
bool str_to_uint_safe(char* str, unsigned int* out) {
	char* nonnumber_chars;
	unsigned long result = strtoul(str, &nonnumber_chars, 0);
	if (result > UINT_MAX) return false; // number won't fit in uint.
	if (strlen(nonnumber_chars) != 0) return false; // if there are extraneous characters, the number was invalid.
	*out = (unsigned int)result;
	return true;
}
