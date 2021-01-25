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
#include <ctype.h>
#include <math.h>
#include "util.h"
#include "rsa.h"
#include "main.h"

bool get_prime(unsigned int* const result) {
	verbose_log("getting a prime\n");
	for (unsigned short r = GET_PRIME_TRIES; r > 0; r --) {
		const unsigned int n = get_number_in_prime_range();
		verbose_logf("got %u which was...\n", n);
		if (is_prime(n)) {
			verbose_log("...prime, so returning it\n");
			*result = n;
			return true;
		}
		verbose_log("...probably not prime\n");
	}
	return false;
}

unsigned int rsa_encrypt(const char plain, const unsigned int key, const unsigned int modulus) {
	verbose_logf(isprint(plain) ? "encrypting %c with %u %% %u\n" : "encrypting non-print (hex %02x) with %u %% %u\n", plain, key, modulus);
	return mod_pow((unsigned long)plain, key, modulus);
}

char rsa_decrypt(const unsigned int cipher, const unsigned int key, const unsigned int modulus) {
	verbose_logf("decrypting %u with %u %% %u\n", cipher, key, modulus);
	return (char)mod_pow(cipher, key, modulus);
}

void rsa_keygen(struct KeygenResult* const result) {
	verbose_log("generating keys\n");
	get_prime(&(result->p));
	verbose_logf("got p %u\n", result->p);
	do {
		get_prime(&(result->q));
		verbose_logf("trying q %u\n", result->q);
	} while(result->p == result->q);
	verbose_logf("final q was %u\n", result->q);
	result->modulo = result->p * result->q;
	verbose_logf("modulus is %u\n", result->modulo);
	const unsigned int totient = (result->p - 1) * (result->q - 1);
	verbose_logf("totient is %u\n", totient);
	do {
		result->public = randrange(1, totient);
		verbose_logf("trying public key %u\n", result->public);
	} while (gcd(result->public, totient) != 1);

	result->private = multiplicative_inverse(result->public, totient);
}
