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
#ifndef MAIN_H_INCLUDED
#define MAIN_H_INCLUDED

#define EXIT_USAGE_ERROR 2
#define EXIT_INTERNAL_ERROR 1
#define EXIT_EOF_INPUT 0

#define VERSION_STRING "rsa, by Matt Fellenz\nversion 0.1-alpha\nlicensed under the GPL v3.0"

enum e_verbosity {
	VERBOSE,
	DEFAULT,
	QUIET
};

extern enum e_verbosity verbosity;

#endif
