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

enum e_verbosity verbosity = DEFAULT;

int main(int argc, char** argv) {
	/* -v, --verbose : set verbosity to VERBOSE
	   -b, --brief : set verbosity to DEFAULT (only useful after -v or -q)
	   -q, --quiet : set verbosity to QUIET
	   -V, --version : print version and exit
	   -h, --help, --usage : print usage and exit */
	// ↓ stores pointers to the text arguments (as opposed to options)
	char* text_args[5]; // max number of text args is (I believe) three, so five is plenty.
	int text_arg_index = 0;
	bool wants_help = false;
	for (int arg_pos = 1; arg_pos < argc; arg_pos++) {
		char* this_arg = argv[arg_pos];
		if (this_arg[0] == '-') { // starts with -, short or long option (or just - or --)
			if (this_arg[1] == '-') { // starts with --, long option (or just --)
				if (this_arg[2] == '\0') { // just --, disqualifies anything following as an argument
					arg_pos++; // exclude this argument
					// copy item-by-item to text_args the following arguments until end of argc
					// if there are too many arguments to fit into text_args, ignore them because there are too many anyway (max 3).
					for (int i = text_arg_index; arg_pos < argc && i < 5; i++, arg_pos++) {
						text_args[i] = argv[arg_pos];
					}
					break;
				} else { // long option
					this_arg += 2 * sizeof(char); // exclude -- prefix
					if (streq(this_arg, "verbose")) verbosity = VERBOSE;
					else if (streq(this_arg, "brief")) verbosity = DEFAULT;
					else if (streq(this_arg, "quiet")) verbosity = QUIET;
					else if (streq(this_arg, "version")) { puts(VERSION_STRING); exit(0); }
					else if (streq(this_arg, "help") || streq(this_arg, "usage")) wants_help = true;
					else print_generic_usage_with_complaint_and_readback_string("unrecognized option", this_arg - (2 * sizeof(char)));
					continue; // redundant
				}
			} else if (this_arg[1] == '\0') { // just -, not actually an option
				text_args[text_arg_index] = this_arg;
				text_arg_index++;
				continue;
			} else { // short option(s)
				this_arg += sizeof(char); // exclude - prefix
				for(; this_arg[0] != '\0'; this_arg += sizeof(char)) { // process while this_arg still has characters
					switch (this_arg[0]) {
						case 'v': verbosity = VERBOSE; break;
						case 'b': verbosity = DEFAULT; break;
						case 'q': verbosity = QUIET; break;
						case 'V': puts(VERSION_STRING); exit(0);
						case 'h': wants_help = true; break;
						default: print_generic_usage_with_complaint_and_readback_short_option("unrecognized option", this_arg[0]); // exits
					}
				}
			}
		} else { // normal argument
		if (text_arg_index == 5) continue; // ignore extra arguments
			text_args[text_arg_index] = this_arg;
			text_arg_index++;
			continue; // redundant
		}
	}
	if (text_arg_index == 0) {
		print_generic_usage_with_complaint("no action provided");
	} else {
		if (streq(text_args[0], "keygen")) {
			if (__builtin_expect(wants_help, 0)) print_specific_usage(KEYGEN, false);
			struct KeygenResult result;
			rsa_keygen(&result);
			printf(verbosity == QUIET ? "%u\n%u\n%u\n" : "public key: %u\nprivate key: %u\nmodulus: %u\n", result.public, result.private, result.modulo);
		} else {
			bool are_encrypting = streq(text_args[0], "encrypt");
			if (are_encrypting || streq(text_args[0], "decrypt")) {
				if (__builtin_expect(wants_help, 0)) print_specific_usage(are_encrypting ? ENCRYPT : DECRYPT, false);
				verbose_log("encrypting or decrypting\n");
				if (text_arg_index < 4) {
					print_specific_usage(are_encrypting ? ENCRYPT : DECRYPT, true);
				}
				unsigned int key;
				if(!str_to_uint_safe(text_args[1], &key))
					print_specific_usage(are_encrypting ? ENCRYPT : DECRYPT, true);
				verbose_logf("got key %u\n", key);

				unsigned int mod;
				if(!str_to_uint_safe(text_args[2], &mod))
					print_specific_usage(are_encrypting ? ENCRYPT : DECRYPT, true);
				verbose_logf("got modulus %u\n", mod);

				bool from_stdin = streq(text_args[3], "-");
				if (are_encrypting) {
					verbose_log("encrypting ");
					if (from_stdin) {
						verbose_log("from stdin\n");
						int first, second = getchar();
						if (second == EOF) {
							verbose_log("got no input\n");
							exit(EXIT_EOF_INPUT); // got no input
						}
						verbose_logf("got character %c\n", second);
						while (second != EOF) {
							first = second;
							second = getchar();
							verbose_logf("got character %c\n", second);
							printf("%u", rsa_encrypt((char)first, key, mod));
							if (second != EOF) putchar(' ');
						}
						verbose_log("got eof\n");
					} else {
						verbose_log("from argv\n");
						for (char* current_char_ptr = text_args[3]; *current_char_ptr != 0; current_char_ptr += sizeof(char)) {
							printf("%u ", rsa_encrypt(*current_char_ptr, key, mod));
						}
						verbose_log("adding trailing newline\n");
						printf("%u", rsa_encrypt('\n', key, mod)); // add a trailing newline when receiving plaintext as an argument.
					}
					putchar('\n'); // customary newline on output
					exit(EXIT_SUCCESS);
				} else { // decrypting
					verbose_log("decrypting ");
					if (from_stdin) {
						verbose_log("from stdin\n");
						unsigned int parsed;
						int scan_result = scanf("%u", &parsed);
						if (scan_result == EOF) {
							verbose_log("got no input\n");
							exit(EXIT_EOF_INPUT);
						}
						while (scan_result != EOF) {
							if (scan_result == 0) {
								fputs("got invalid ciphertext number, i.e., was not a number\n", stderr);
								print_specific_usage(DECRYPT, true);
							}
							if (scan_result == -1) {
								perror("OS error");
								exit(EXIT_INTERNAL_ERROR);
							}
							putchar(rsa_decrypt(parsed, key, mod));
							scan_result = scanf("%u", &parsed);
						}
					} else {
						verbose_log("from argv\n");
						unsigned int parsed;
						char* end_ptr = text_args[3] + sizeof(char) * strlen(text_args[3]);
						int chars_consumed;
						for (char* current_char_ptr = text_args[3]; current_char_ptr < end_ptr; current_char_ptr += chars_consumed) {
							if (sscanf(current_char_ptr, "%u%n", &parsed, &chars_consumed) == 0) {
								fputs("got invalid ciphertext number, i.e., was not a number\n", stderr);
								print_specific_usage(DECRYPT, true);
							}
							putchar(rsa_decrypt(parsed, key, mod));
						}
					}
				}
			} else {
				print_generic_usage_with_complaint_and_readback_string("unknown action", text_args[0]);
			}
		}
	}
}
