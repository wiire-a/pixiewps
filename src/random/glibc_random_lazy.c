/*
 * Based on the code of Peter Selinger
 * Reference: http://www.mathstat.dal.ca/~selinger/random/
 *
 * The original code was modified to achieve better speed
 */

#include <stdint.h>

struct glibc_lazyprng {
	int state[344];
};

/*
 * Return 1st generated element only
 */
static unsigned int glibc_rand1(struct glibc_lazyprng *prng)
{
	const int *state = prng->state;
	return ((unsigned int)(state[344 - 31] + state[344 - 3])) >> 1;
}

/*
 * Fill a 4 elements array (to use with memcmp)
 */
static int *glibc_randfill(struct glibc_lazyprng *prng, uint32_t *arr)
{
	int *state = prng->state;
	int const first = state[344 - 31] + state[344 - 3];
	arr[0] = ((unsigned int)first) >> 1;
	arr[1] = ((unsigned int)(state[344 - 31 + 1] + state[342 - 31] + state[342 - 3])) >> 1;
	arr[2] = ((unsigned int)(state[344 - 31 + 2] + state[343 - 31] + state[343 - 3])) >> 1;
	arr[3] = ((unsigned int)(state[344 - 31 + 3] + first))  >> 1;
	return arr;
}

/*
 * Lazy seeding (stay 2 shorter)
 */
static void glibc_lazyseed(struct glibc_lazyprng *prng, int seed)
{
	int *state = prng->state;
	int i = 0;
	state[i++] = seed;
	for ( ; i < 31; i++) {
		state[i] = (16807LL * state[i - 1]) % 2147483647;
		if (state[i] < 0)
			state[i] += 2147483647;
	}
	for (i = 31; i < 34;          i++) state[i] = state[i - 31];
	for (i = 34; i < 344 - 3 + 1; i++) state[i] = state[i - 31] + state[i - 3];
}
