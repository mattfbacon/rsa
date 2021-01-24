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
#include <ctype.h>
#include "util.h"
#include "rsa.h"
#include "main.h"

enum e_verbosity verbosity = DEFAULT;

int main(int argc, char** argv) {
	/* -v, --verbose : set verbosity to VERBOSE
	   -b, --brief : set verbosity to DEFAULT (only useful after -v or -q)
	   -q, --quiet : set verbosity to QUIET
	   -V, --version : print version and exit
	   -h, --help, --usage : print usage and exit
	   -f<arg>, --format <arg> : the format of plaintext, either `chars` (default, raw characters) or `numbers` (unsigned ints). The ciphertext is always in numbers format due to technical restrictions.
	   -d<arg>, --delimiter <arg> : the delimiter between the numbers when in numbers mode. A space by default. Can't include digits.
	*/
	// ↓ stores pointers to the text arguments (as opposed to options)
	char* text_args[5]; // max number of text args is (I believe) three, so five is plenty.
	int text_arg_index = 0;
	bool wants_help = false;
	enum e_data_format data_format = CHARS;
	char* delimiter = " ";
	for (int arg_pos = 1; arg_pos < argc; arg_pos++) {
		char* this_arg = argv[arg_pos];
		if (this_arg[0] == '-') { // starts with -, short or long option (or just - or --)
			if (this_arg[1] == '-') { // starts with --, long option (or just --)
				if (this_arg[2] == '\0') { // just --, disqualifies anything following as an argument
					arg_pos++; // exclude this argument
					// copy item-by-item to text_args the following arguments until end of argc
					// if there are too many arguments to fit into text_args, ignore them because there are too many anyway (max 3).
					for (; arg_pos < argc && text_arg_index < 5; text_arg_index++, arg_pos++) {
						text_args[text_arg_index] = argv[arg_pos];
					}
					break;
				} else { // long option
					this_arg += 2 * sizeof(char); // exclude -- prefix
					if (streq(this_arg, "verbose")) verbosity = VERBOSE;
					else if (streq(this_arg, "brief")) verbosity = DEFAULT;
					else if (streq(this_arg, "quiet")) verbosity = QUIET;
					else if (streq(this_arg, "version")) { puts(VERSION_STRING); exit(0); }
					else if (streq(this_arg, "help") || streq(this_arg, "usage")) wants_help = true;
					else {
						bool was_format = streq(this_arg, "format");
						if (was_format || streq(this_arg, "delimiter")) {
							if (arg_pos + 1 >= argc) print_generic_usage_with_complaint_and_readback_string("argument required for option", this_arg - 2 * sizeof(char)); // off-by-one? couldn't be me
							this_arg = argv[++arg_pos];
							if (was_format) {
								if (streq(this_arg, "numbers")) data_format = NUMBERS;
								else if (streq(this_arg, "chars")) data_format = CHARS;
								else print_generic_usage_with_complaint_and_readback_string("unknown argument to option '--format'", this_arg);
							} else { // delimiter
								delimiter = this_arg;
							}
						} else print_generic_usage_with_complaint_and_readback_string("unrecognized option", this_arg - (2 * sizeof(char)));
					}
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
						case 'f':
							// allow -fchars and -f chars
							this_arg += sizeof(char); // exclude f
							if (this_arg[0] == '\0') { // e.g., -f chars, so make this_arg point to the next argv item
								if (arg_pos + 1 >= argc) print_generic_usage_with_complaint("argument required for option '-f'"); // off-by-one? couldn't be me
								this_arg = argv[++arg_pos];
								if (this_arg[0] == '-') print_generic_usage_with_complaint("argument required for option '-f'"); // it's not the argument, it's another option
							} // else, e.g., -fchars, so just use the rest of this_arg.
							bool was_chars = strstartswith(this_arg, "chars");
							if (was_chars || strstartswith(this_arg, "numbers")) {
								data_format = was_chars ? CHARS : NUMBERS;
								this_arg += was_chars ? strlen("chars") : strlen("numbers");
								if (*this_arg == '\0') // end of this arg
									goto loop_exit;
								else { // we already got chars or numbers, so why not check for more args if people like living on the edge?
									this_arg -= sizeof(char); // cancel out last clause of for loop
									break; // break the switch, continue the for
								}
							} // in both cases we don't want to continue parsing arguments
							print_generic_usage_with_complaint_and_readback_string("unknown argument to option '-f'", this_arg);
							break; // redundant
						case 'd':
							// since the argument is an arbitrary string the parsing algorithm is a bit different.
							this_arg += sizeof(char); // exclude d
							if (this_arg[0] == '\0') { // e.g., -d ', '
								if (arg_pos + 1 >= argc) print_generic_usage_with_complaint("argument required for option '-d'"); // off-by-one? couldn't be me
								this_arg = argv[++arg_pos];
								// to allow for a dash delimiter, the next argv item is treated as -d's argument whether or not it starts with a dash.
							} // else, the delimiter is the rest of the string (e.g., -d', '), so don't touch this_arg
							delimiter = this_arg;
							goto loop_exit; // no one asked you if goto is bad
						default: print_generic_usage_with_complaint_and_readback_short_option("unrecognized option", this_arg[0]); // exits
					}
				}
				loop_exit: ;
			}
		} else { // normal argument
		if (text_arg_index == 5) continue; // ignore extra arguments
			text_args[text_arg_index] = this_arg;
			text_arg_index++;
			continue; // redundant
		}
	}
	for(char* i = delimiter; *i != '\0'; i += sizeof(char)) {
		if (isdigit(*i)) {
			print_generic_usage_with_complaint_and_readback_string("delimiter cannot include digits; got", delimiter);
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
							if (second != EOF) fputs(delimiter, stdout);
						}
						verbose_log("got eof\n");
					} else {
						verbose_log("from argv\n");
						for (char* current_char_ptr = text_args[3]; *current_char_ptr != 0; current_char_ptr += sizeof(char)) {
							printf("%u", rsa_encrypt(*current_char_ptr, key, mod));
							fputs(delimiter, stdout);
						}
						verbose_log("adding trailing newline\n");
						printf("%u", rsa_encrypt('\n', key, mod)); // add a trailing newline when receiving plaintext as an argument.
					}
					putchar('\n'); // customary newline on output
					exit(EXIT_SUCCESS);
				} else { // decrypting
					verbose_log("decrypting ");
					char escaped_delimiter[2 * strlen(delimiter)];
					str_scanf_escape(delimiter, escaped_delimiter);
					if (from_stdin) {
						verbose_log("from stdin\n");
						unsigned int parsed;
						int scan_result = scanf("%u", &parsed);
						if (scan_result == EOF) {
							verbose_log("got no input\n");
							exit(EXIT_EOF_INPUT);
						}
						scanf(escaped_delimiter);
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
							scanf(escaped_delimiter);
						}
					} else {
						verbose_log("from argv\n");
						char full_scanf_string[4 + strlen(escaped_delimiter)];
						strcpy(full_scanf_string, "%u");
						strcat(full_scanf_string, escaped_delimiter);
						strcat(full_scanf_string, "%n");
						unsigned int parsed;
						char* end_ptr = text_args[3] + sizeof(char) * strlen(text_args[3]);
						int chars_consumed;
						for (char* current_char_ptr = text_args[3]; current_char_ptr < end_ptr; current_char_ptr += chars_consumed) {
							if (sscanf(current_char_ptr, full_scanf_string, &parsed, &chars_consumed) == 0) {
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
