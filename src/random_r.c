/*
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by the University of California, Berkeley. The name of the
 * University may not be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

/*
 * This is derived from the Berkeley source:
 *	@(#)random.c	5.5 (Berkeley) 7/6/88
 * It was reworked for the GNU C Library by Roland McGrath.
 * Rewritten to be reentrant by Ulrich Drepper, 1995
 */

/*
 * This file is part of pixiewps and was modified
 */

#include <limits.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
# include <sys/param.h>
# if defined(BSD) || defined(__APPLE__) && defined(__MACH__)
	/* Nothing to include */
#else
# include <features.h>
# endif
#endif

#include <stdint.h>

struct m_random_data {
	int32_t *fptr;     /* Front pointer */
	int32_t *rptr;     /* Rear pointer */
	int32_t *state;    /* Array of state values */
	int32_t *end_ptr;  /* Pointer behind state table */
};

/* x**31 + x**3 + 1 */
#define TYPE_3     3
#define BREAK_3    128
#define DEG_3      31
#define SEP_3      3

#define MAX_TYPES  5  /* Max number of types */

/* We do our fancy trinomial stuff, which is the
   same in all the other cases due to all the global variables that have been
   set up. The basic operation is to add the number at the rear pointer into
   the one at the front pointer. Then both pointers are advanced to the next
   location cyclically in the table. The value returned is the sum generated,
   reduced to 31 bits by throwing away the "least random" low bit.
   Note: The code takes advantage of the fact that both the front and
   rear pointers can't wrap on the same call by not testing the rear
   pointer if the front one has wrapped. Returns a 31-bit random number. */
void m_random_r(struct m_random_data *buf, int32_t *result)
{
	int32_t *state = buf->state;
	int32_t *fptr = buf->fptr;
	int32_t *rptr = buf->rptr;
	int32_t *end_ptr = buf->end_ptr;
	int32_t val = *fptr += *rptr;

	/* Chucking least random bit.  */
	*result = (val >> 1) & 0x7fffffff;
	++fptr;
	if (fptr >= end_ptr) {
		fptr = state;
		++rptr;
	}
	else {
		++rptr;
		if (rptr >= end_ptr)
			rptr = state;
	}
	buf->fptr = fptr;
	buf->rptr = rptr;
}

/* Initializes state[] based on the given "seed" via a linear
   congruential generator. Then, the pointers are set to known locations
   that are exactly rand_sep places apart. Lastly, it cycles the state
   information a given number of times to get rid of any initial dependencies
   introduced by the L.C.R.N.G. Note that the initialization of randtbl[]
   for default usage relies on values produced by this routine. */
void m_srandom_r(unsigned int seed, struct m_random_data *buf)
{
	long int word;
	int i, kc;
	int32_t *dst;
	int32_t *state = buf->state;

	/* We must make sure the seed is not 0. Take arbitrarily 1 in this case. */
	if (seed == 0)
		seed = 1;

	state[0] = seed;
	dst = state;
	word = seed;
	for (i = 1; i < DEG_3; ++i) {
		/* This does:
		   state[i] = (16807 * state[i - 1]) % 2147483647;
		   but avoids overflowing 31 bits */
		long int hi = word / 127773;
		long int lo = word % 127773;
		word = 16807 * lo - 2836 * hi;
		if (word < 0)
			word += 2147483647;
		*++dst = word;
	}

	buf->fptr = &state[SEP_3];
	buf->rptr = &state[0];
	kc = DEG_3 * 10;
	while (--kc >= 0) {
		int32_t discard;
		(void)m_random_r(buf, &discard);
	}
}

/* Initialize the state information in the given array of N bytes for
   future random number generation. Based on the number of bytes we
   are given, and the break values for the different R.N.G.'s, we choose
   the best (largest) one we can and set things up for it. srandom is
   then called to initialize the state information. Note that on return
   from srandom, we set state[-1] to be the type multiplexed with the current
   value of the rear pointer; this is so successive calls to initstate won't
   lose this information and will be able to restart with setstate.
   Note: The first thing we do is save the current state, if any, just like
   setstate so that it doesn't matter when initstate is called.
   Returns a pointer to the old state. */
void m_initstate_r(unsigned int seed, char *arg_state, struct m_random_data *buf)
{
	int type;
	int degree;
	int separation;
	int32_t *state = &((int32_t *)arg_state)[1];  /* First location */

	/* Must set END_PTR before srandom */
	buf->end_ptr = &state[DEG_3];
	buf->state = state;

	m_srandom_r(seed, buf);

	state[-1] = (buf->rptr - state) * MAX_TYPES + TYPE_3;
}
