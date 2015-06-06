/*
 * Pixiewps: bruteforce the wps pin exploiting the low or non-existing entropy of some APs (pixie dust attack).
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

#ifndef RANDOM_R_H
#define RANDOM_R_H

#include <stdint.h>

struct random_data {
  int32_t *fptr;    /* Front pointer */
  int32_t *rptr;    /* Rear pointer */
  int32_t *state;   /* Array of state values */
  int rand_type;    /* Type of random number generator */
  int rand_deg;     /* Degree of random number generator */
  int rand_sep;     /* Distance between front and rear */
  int32_t *end_ptr; /* Pointer behind state table */
};

void random_r(struct random_data *buf, int32_t *result);
int srandom_r(unsigned int seed, struct random_data *buf);
int initstate_r(unsigned int seed, char *arg_state, size_t n, struct random_data *buf);
int setstate_r(char *arg_state, struct random_data *buf);

#endif /* RANDOM_R_H */
