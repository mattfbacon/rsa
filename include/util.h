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

bool rabin_miller_check(unsigned int a, unsigned int s, unsigned int d, unsigned int n);
bool rabin_miller(unsigned int n);
bool is_prime(unsigned int n);
unsigned int gcd(unsigned int a, unsigned int b);
unsigned int multiplicative_inverse(unsigned int a, unsigned int b);

unsigned int mod_pow(unsigned long base, unsigned int exp, unsigned int mod);
unsigned int get_random(unsigned int max);
void print_generic_usage_with_complaint_and_readback_short_option(char* complaint, char option_name);
void print_generic_usage_with_complaint_and_readback_string(char* complaint, char* content);
void print_generic_usage_with_complaint(char* complaint);
void print_generic_usage();
bool streq(char* str1, char* str2);
bool str_to_uint_safe(char* str, unsigned int* out);

#endif
