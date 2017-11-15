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

#define GLIBC_PRNG_SIZE     344
#define GLIBC_FAST_MAX_GEN    3

#if GLIBC_MAX_GEN < GLIBC_FAST_MAX_GEN
	#error "GLIBC_MAX_GEN must be >= GLIBC_FAST_MAX_GEN"
#endif

/*
 * The +1 is used to keep the index inside the array after the increment,
 * it doesn't really have a purpose besides that
 */
struct glibc_prng {
	int index;
	int state[GLIBC_PRNG_SIZE + GLIBC_MAX_GEN - GLIBC_FAST_MAX_GEN + 1];
};

/*
 * If only 3 numbers are generated then there's no need to store new values
 */
unsigned int glibc_rand_fast(struct glibc_prng *prng)
{
	const int *state = prng->state;
	const int i = prng->index++;
	return ((unsigned int)(state[i - 31] + state[i - 3])) >> 1;
}

/*
 * There are no checks of bounds (GLIBC_MAX_GEN is the maximum number of times it can be called)
 */
unsigned int glibc_rand(struct glibc_prng *prng)
{
	int *state = prng->state;
	const int i = prng->index++;
	state[i] = state[i - 31] + state[i - 3];
	return (unsigned int)state[i] >> 1;
}

void glibc_seed(struct glibc_prng *prng, int seed)
{
	int i;
	int *state = prng->state;
	prng->index = GLIBC_PRNG_SIZE;
	state[0] = seed;
    for (i = 1; i < 31; i++) {
      state[i] = (16807LL * state[i - 1]) % 2147483647;
      if (state[i] < 0)
        state[i] += 2147483647;
    }
    for (i = 31; i < 34;  i++) state[i] = state[i - 31];
    for (i = 34; i < 344; i++) state[i] = state[i - 31] + state[i - 3];
}
