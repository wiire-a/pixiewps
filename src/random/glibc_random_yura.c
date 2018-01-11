/*
 * Based on the code of user @1yura.
 *
 * See glibc_random.c for a better understanding of the code.
 */

#include <stdint.h>

static const uint32_t glibc_seed_tbl[31 + 3] = {
		0x0128e83b, 0x00dafa31, 0x009f4828, 0x00f66443, 0x00bee24d, 0x00817005, 0x00cb918f,
		0x00a64845, 0x0069c3cf, 0x00a76dbd, 0x0090a848, 0x0057025f, 0x0089126c, 0x007d9a8f,
		0x0048252a, 0x006fb2d4, 0x006ccc15, 0x003c5744, 0x005a998f, 0x005df917, 0x0032ed77,
		0x00492688, 0x0050e901, 0x002b5f57, 0x003acd0b, 0x00456b7a, 0x0025413d, 0x002f11f4,
		0x003b564d, 0x00203f14, 0x002589fc, 0x003283f8, 0x001c17e4, 0x001dd823
};

static inline uint32_t *glibc_fast_nonce(uint32_t seed, uint32_t *dest)
{
	uint32_t word0 = 0, word1 = 0, word2 = 0, word3 = 0;

#ifdef PWPS_UNERRING
	if      (seed == 0x7fffffff) seed = 0x13f835f3;
	else if (seed == 0xfffffffe) seed = 0x5df735f1;
#endif

	for (int j = 0; j < 31; j++) {
		word0 += seed * glibc_seed_tbl[j + 3];
		word1 += seed * glibc_seed_tbl[j + 2];
		word2 += seed * glibc_seed_tbl[j + 1];
		word3 += seed * glibc_seed_tbl[j + 0];

		/* This does: seed = (16807LL * seed) % 0x7fffffff
		   using the sum of digits method which works for mod N, base N+1 */
		/* Doesn't work for seed = 0x7fffffff or 0xfffffffe */
		uint64_t p = 16807ULL * seed;
		p = (p >> 31) + (p & 0x7fffffff);
		seed = (p >> 31) + (p & 0x7fffffff);
	}
	dest[0] = word0 >> 1;
	dest[1] = word1 >> 1;
	dest[2] = word2 >> 1;
	dest[3] = word3 >> 1;
	return dest;
}

static inline uint32_t glibc_fast_seed(uint32_t seed)
{
	uint32_t word0 = 0;

#ifdef PWPS_UNERRING
	if      (seed == 0x7fffffff) seed = 0x13f835f3;
	else if (seed == 0xfffffffe) seed = 0x5df735f1;
#endif

	for (int j = 3; j < 31 + 3 - 1; j++) {
		word0 += seed * glibc_seed_tbl[j];

		/* This does: seed = (16807LL * seed) % 0x7fffffff
		   using the sum of digits method which works for mod N, base N+1 */
		/* Doesn't work for seed = 0x7fffffff or 0xfffffffe */
		uint64_t p = 16807ULL * seed;
		p = (p >> 31) + (p & 0x7fffffff);
		seed = (p >> 31) + (p & 0x7fffffff);
	}
	return (word0 + seed * glibc_seed_tbl[33]) >> 1;
}
