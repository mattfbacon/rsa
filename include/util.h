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
#ifndef UTIL_H_INCLUDED
#define UTIL_H_INCLUDED

#include <stdbool.h>

#define RABIN_MILLER_TRIES 10

#define randrange(a, b) (get_random(b - a) + a); // [a, b), like python randrange

unsigned int get_random(const unsigned int max);

bool is_prime(const unsigned int n);
unsigned int gcd(unsigned int a, unsigned int b);
unsigned int multiplicative_inverse(unsigned int a, unsigned int b);

enum e_command {
	ENCRYPT,
	DECRYPT,
	KEYGEN
};

typedef const char*restrict const immutable_string_t;

unsigned int mod_pow(unsigned long base, unsigned int exp, const unsigned int mod);

void print_generic_usage_with_complaint_and_readback_short_option(immutable_string_t complaint, const char option_name);
void print_generic_usage_with_complaint_and_readback_string(immutable_string_t complaint, immutable_string_t content);
void print_generic_usage_with_complaint(immutable_string_t complaint);
void print_generic_usage(const bool in_error);
void print_specific_usage(const enum e_command command, const bool in_error);
bool streq(immutable_string_t str1, immutable_string_t str2);
bool strstartswith(const char*restrict str, const char*restrict pre);
bool str_to_uint_safe(immutable_string_t str, unsigned int* const out);

void str_scanf_escape(const char*restrict str, char*restrict out);

#endif
