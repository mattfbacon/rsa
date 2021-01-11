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
#include <math.h>
#include "util.h"
#include "rsa.h"
#include "main.h"

bool get_prime(unsigned int *result) {
	for (unsigned short r = GET_PRIME_TRIES; r > 0; r -= 1) {
		unsigned int n = get_number_in_prime_range();
		if (is_prime(n)) {
			*result = n;
			return true;
		}
	}
	return false;
}

unsigned int rsa_encrypt(char plain, unsigned int key, unsigned int modulus) {
	return mod_pow((unsigned long)plain, key, modulus);
}

char rsa_decrypt(unsigned int cipher, unsigned int key, unsigned int modulus) {
	return (char)mod_pow(cipher, key, modulus);
}

void rsa_keygen(struct KeygenResult* result) {
	get_prime(&(result->p));
	do {
		get_prime(&(result->q));
	} while(result->p == result->q);
	result->modulo = result->p * result->q;
	const unsigned int totient = (result->p - 1) * (result->q - 1);
	do {
		result->public = randrange(1, totient);
	} while (gcd(result->public, totient) != 1);

	result->private = multiplicative_inverse(result->public, totient);
}
