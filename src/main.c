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
#include <errno.h>
#include "util.h"
#include "rsa.h"
#include "main.h"

int main(int argc, char** argv) {
	if (argc >= 1 + 1) {
		if (streq(argv[1], "keygen")) {
			struct KeygenResult result;
			rsa_keygen(&result);
			printf("public key: %u\nprivate key: %u\nmodulus: %u\n", result.public, result.private, result.modulo);
		} else {
			bool are_encrypting = streq(argv[1], "encrypt");
			if (are_encrypting || streq(argv[1], "decrypt")) {
				if (argc < 4 + 1) {
					fputs("rsa: not enough arguments for \"", stdout);
					fputs(argv[1], stdout);
					puts("\"");
					print_generic_usage();
				}
				unsigned int key;
				if(!str_to_uint_safe(argv[2], &key))
					print_generic_usage_with_complaint("key must be unsigned int");

				unsigned int mod;
				if(!str_to_uint_safe(argv[3], &mod))
					print_generic_usage_with_complaint("modulus must be unsigned int");

				bool from_stdin = streq(argv[4], "-");
				if (are_encrypting) {
					if (from_stdin) {
						char first, second = getchar();
						if (second == EOF) exit(EXIT_EOF_INPUT); // got no input
						while (second != EOF) {
							first = second;
							second = getchar();
							printf("%u", rsa_encrypt(first, key, mod));
							if (second != EOF) putchar(' ');
						}
					} else {
						for (char* current_char_ptr = argv[4]; *current_char_ptr != 0; current_char_ptr += sizeof(char)) {
							printf("%u ", rsa_encrypt(*current_char_ptr, key, mod));
						}
						printf("%u", rsa_encrypt('\n', key, mod)); // add a trailing newline when receiving plaintext as an argument.
					}
					putchar('\n'); // customary newline on output
					exit(EXIT_SUCCESS);
				} else { // decrypting
					if (from_stdin) {
						unsigned int parsed;
						int scan_result = scanf("%u", &parsed);
						if (scan_result == EOF) exit(EXIT_EOF_INPUT);
						while (scan_result != EOF) {
							if (scan_result == 0) {
								puts("rsa: got invalid ciphertext number, i.e. was not a number");
								exit(EXIT_USAGE_ERROR);
							}
							if (scan_result == -1) {
								perror("OS error");
								exit(EXIT_INTERNAL_ERROR);
							}
							putchar(rsa_decrypt(parsed, key, mod));
							scan_result = scanf("%u", &parsed);
						}
					} else {
						unsigned int parsed;
						char* end_ptr = argv[4] + sizeof(char) * strlen(argv[4]);
						int chars_consumed;
						for (char* current_char_ptr = argv[4]; current_char_ptr < end_ptr; current_char_ptr += chars_consumed) {
							if (sscanf(current_char_ptr, "%u%n", &parsed, &chars_consumed) == 0) {
								puts("rsa: got invalid ciphertext number, i.e. was not a number");
								exit(EXIT_USAGE_ERROR);
							}
							putchar(rsa_decrypt(parsed, key, mod));
						}
					}
				}
			} else {
				fputs("rsa: unknown action \"", stdout);
				fputs(argv[1], stdout);
				puts("\"");
				print_generic_usage();
			}
		}
	} else {
		print_generic_usage_with_complaint("no action provided");
	}
	/*
	switch (argc) {
		case 1:
			print_generic_usage_with_complaint("no action provided");
			break;
		case 2:
			if (streq(argv[1], "keygen"))
		case 3:
		case 4:;
			const bool are_encrypting = streq(argv[1], "encrypt");
			if (are_encrypting || streq(argv[1], "decrypt")) { 
				printf("rsa: not enough arguments for %1$s\nUsage:\n\t%1$s <key> <modulo> <%2$s>\n", argv[1], are_encrypting ? "plaintext" : "ciphertext");
			} else {
				print_generic_usage_with_complaint("unknown action");
			}
			exit(EXIT_USAGE_ERROR);
		case 5:
			bool are_encrypting = streq(argv[1], "encrypt");
			if (are_encrypting || streq(argv[1], "decrypt")) {
				bool use_stdin = streq(argv[4], "-");

				bool valid;
				unsigned long key = str_to_long_safe(argv[2], &valid);
				if (!valid) {
					char* key_complaint;
					sprintf(key_complaint, "key must be unsigned long, got \"%s\"", argv[2]);
					print_generic_usage_with_complaint(key_complaint);
				}
				unsigned long modulo = str_to_long_safe(argv[3], &valid);
				if (!valid) {
					char* mod_complaint;
					sprintf(mod_complaint, "modulo must be unsigned long, got \"%s\"", argv[3]);
					print_generic_usage_with_complaint(mod_complaint);
				}


			} else {
				print_generic_usage_with_complaint("unknown action");
			}
			break;
		default:
			print_generic_usage_with_complaint("too many arguments");
	}
	*/
}
