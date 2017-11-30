/*
 * Based on the code of Peter Selinger
 * Reference: http://www.mathstat.dal.ca/~selinger/random/
 *
 * The original code was modified to achieve better speed
 *
 * Note that in the original code two signed integers are added together
 * which results in undefined behavior if the sum overflows the content
 * of a signed integer while trying to preserve the sign.
 *
 * To avoid this, we exploit the 2's complement, thus using only
 * unsigned integers. Note that INT_MAX + INT_MAX <= UINT_MAX and that
 * adding two unsigned integers which sum exceeds UINT_MAX is not
 * undefined behavior, it causes the value to wrap around.
 */

#include <stdint.h>

struct glibc_lazyprng {
	uint32_t state[344];
};

/*
 * Return 1st generated element only
 */
static uint32_t glibc_rand1(struct glibc_lazyprng *prng)
{
	const uint32_t *state = prng->state;
	return (state[344 - 31] + state[344 - 3]) >> 1;
}

/*
 * Fill a 4 elements array (to use with memcmp)
 */
static uint32_t *glibc_randfill(struct glibc_lazyprng *prng, uint32_t *arr)
{
	uint32_t *state = prng->state;
	const uint32_t first = state[344 - 31] + state[344 - 3];
	arr[0] = first >> 1;
	arr[1] = (state[344 - 31 + 1] + state[342 - 31] + state[342 - 3]) >> 1;
	arr[2] = (state[344 - 31 + 2] + state[343 - 31] + state[343 - 3]) >> 1;
	arr[3] = (state[344 - 31 + 3] + first) >> 1;
	return arr;
}

/*
 * Lazy seeding (stay 2 shorter)
 */
static void glibc_lazyseed(struct glibc_lazyprng *prng, uint32_t seed)
{
	uint32_t *state = prng->state;
	uint32_t i = 0;
	state[i++] = seed;
	for ( ; i < 31; i++) {
		state[i] = (16807LL * state[i - 1]) % 2147483647;
		if (state[i] & 0x80000000)  /* < 0 */
			state[i] += 2147483647;
	}
	for (i = 31; i < 34;          i++) state[i] = state[i - 31];
	for (i = 34; i < 344 - 3 + 1; i++) state[i] = state[i - 31] + state[i - 3];
}
