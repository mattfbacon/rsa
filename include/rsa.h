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
#ifndef RSA_H_INCLUDED
#define RSA_H_INCLUDED

#define PRIME_N_BITS 8 // small primes
#define PRIME_2_N 256 // 2 ^ PRIME_N_BITS
#define PRIME_2_N_1 128 // 2 ^ (PRIME_N_BITS - 1)
#define get_number_in_prime_range() randrange(PRIME_2_N_1, PRIME_2_N)

#define GET_PRIME_TRIES 400 // ceil(100 * (log2(PRIME_N_BITS) + 1)

struct KeygenResult {
	unsigned int public;
	unsigned int private;
	unsigned int modulo; // aka pq or n
	unsigned int p;
	unsigned int q;
};

bool get_prime(unsigned int *result);
unsigned int rsa_encrypt(char plain, unsigned int key, unsigned int modulus);
char rsa_decrypt(unsigned int cipher, unsigned int key, unsigned int modulus);
void rsa_keygen(struct KeygenResult* result);

#endif
