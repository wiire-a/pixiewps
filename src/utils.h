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
#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>

/* Convert an hex string to a byte array */
unsigned int hex_string_to_byte_array(char *in, uint8_t *out, const unsigned int n_len)
{
	unsigned int len = strlen(in);
	unsigned int b_len = n_len * 2 + n_len - 1;

	if (len != n_len * 2 && len != b_len)
		return 1;
	for (unsigned int i = 0; i < n_len; i++) {
		unsigned char o = 0;
		for (unsigned char j = 0; j < 2; j++) {
			o <<= 4;
			if (*in >= 'A' && *in <= 'F')
				*in += 'a'-'A';
			if (*in >= '0' && *in <= '9')
				o += *in - '0';
			else
				if (*in >= 'a' && *in <= 'f')
					o += *in - 'a' + 10;
				else
					return 1;
			in++;
		}
		*out++ = o;
		if (len == b_len) {
			if (*in == ':' || *in == '-' || *in == ' ' || *in == 0)
				in++;
			else
				return 1;
		}
	}
	return 0;
}

/* Convert an hex string to a byte array */
unsigned int hex_string_to_byte_array_max(
		char *in, uint8_t *out, const unsigned int max_len, unsigned int *m_len)
{
	uint_fast8_t o, separator = 0;
	unsigned int count = 0;
	unsigned int len = strlen(in);

	if (len > 2)
		if (in[2] == ':' || in[2] == '-' || in[2] == ' ')
			separator = 1;
	if (separator) {
		if ((len + 1) / 3 > max_len)
			return 1;
	}
	else {
		if (len / 2 > max_len)
			return 1;
	}

	for (unsigned int i = 0; i < max_len; i++) {
		o = 0;
		for (uint_fast8_t j = 0; j < 2; j++) {
			o <<= 4;
			if (*in >= 'A' && *in <= 'F')
				*in += 'a'-'A';
			if (*in >= '0' && *in <= '9')
				o += *in - '0';
			else
				if (*in >= 'a' && *in <= 'f')
					o += *in - 'a' + 10;
				else
					return 1;
			in++;
		}
		*out++ = o;
		count++;

		if (*in == 0)
			goto end;

		if (separator) {
			if (*in == ':' || *in == '-' || *in == ' ')
				in++;
			else
				return 1;
		}
	}

end:
	*m_len = count;
	return 0;
}

/* Convert a string into an integer */
int get_int(char *in, int *out)
{
	int i, o = 0, len = strlen(in);
	for (i = 0; i < len; i++) {
		if ('0' <= *in && *in <= '9')
			o = o * 10 + *in - '0';
		else
			return 1;
		in++;
	}
	*out = o;
	return 0;
}

unsigned int bit_revert(unsigned int v)
{
	size_t i;
	unsigned int n = 0;
	for (i = 0; i < sizeof(unsigned int) * 8; i++) {
		const unsigned int lsb = v & 1;
		v >>= 1;
		n <<= 1;
		n |= lsb;
	}
	return n;
}

/* Custom timegm function made by Eric S Raymond */
time_t c_timegm(struct tm *t)
{
	long year;
	time_t result;

	#define MONTHS_PER_YEAR 12 /* Months per calendar year */

	static const int cdays[MONTHS_PER_YEAR] =
		{ 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334 };

	year = 1900 + t->tm_year + t->tm_mon / MONTHS_PER_YEAR;
	result = (year - 1970) * 365 + cdays[t->tm_mon % MONTHS_PER_YEAR];
	result += (year - 1968) / 4;
	result -= (year - 1900) / 100;
	result += (year - 1600) / 400;
	if ((year % 4) == 0 && ((year % 100) != 0 || (year % 400) == 0) &&
		(t->tm_mon % MONTHS_PER_YEAR) < 2) {
		result--;
	}
	result += t->tm_mday - 1;
	result *= 24;
	result += t->tm_hour;
	result *= 60;
	result += t->tm_min;
	result *= 60;
	result += t->tm_sec;
	if (t->tm_isdst == 1)
		result -= 3600;

	return result;
}

/* Convert a [mm/]yyyy string to Unix date time */
unsigned int get_unix_datetime(char *s, time_t *datetime)
{
	unsigned int len = strlen(s);
	int month = 0, year;

	if (len == 4) {
		if (get_int(s, &year))
			return 1;
	}
	else if (len == 7) {
		if (s[2] != '/' && s[2] != '-' && s[2] != '.')
			return 1;

		char s_month[3];
		char s_year[5];
		if (s[0] == '0') {
			s_month[0] = s[1];
			s_month[1] = 0;
		}
		else {
			s_month[0] = s[0];
			s_month[1] = s[1];
			s_month[2] = 0;
		}

		s_year[0] = s[3];
		s_year[1] = s[4];
		s_year[2] = s[5];
		s_year[3] = s[6];
		s_year[4] = 0;

		if (get_int(s_month, &month) || get_int(s_year, &year))
			return 1;
		if (year < 1970 || year > 2038 || month < 1 || month > 12 || (month > 2 && year == 2038))
			return 1;
	}
	else {
		return 1;
	}

	if (year == 2038 && month == 2) {
		*datetime = (time_t)0x7fffffff;
	}
	else {
		struct tm t = {
			.tm_year = year - 1900,
			.tm_mon = month - 1,
			.tm_mday = 1 };
		*datetime = c_timegm(&t);

		if (*datetime < 0) /* When time_t is 64 bits this check is pointless */
			return 1;
	}

	return 0;
}

/* Subtract the ‘struct timeval’ values X and Y
   Return 1 if the difference is negative, otherwise 0
   Reference: https://www.gnu.org/software/libc/manual/html_node/Elapsed-Time.html */
int timeval_subtract(struct timeval *result, struct timeval *x, struct timeval *y)
{
	/* Perform the carry for the later subtraction by updating y */
	if (x->tv_usec < y->tv_usec) {
		const int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
		y->tv_usec -= 1000000 * nsec;
		y->tv_sec += nsec;
	}
	if (x->tv_usec - y->tv_usec > 1000000) {
		const int nsec = (x->tv_usec - y->tv_usec) / 1000000;
		y->tv_usec += 1000000 * nsec;
		y->tv_sec -= nsec;
	}

	/* Compute the time remaining to wait, tv_usec is certainly positive */
	result->tv_sec = x->tv_sec - y->tv_sec;
	result->tv_usec = x->tv_usec - y->tv_usec;

	/* Return 1 if result is negative */
	return x->tv_sec < y->tv_sec;
}

/* Convert an unsigned integer to a char array without termination */
static inline void uint_to_char_array(unsigned int num, unsigned int len, char *dst)
{
	unsigned int mul = 1;
	while (len--) {
		dst[len] = (num % (mul * 10) / mul) + '0';
		mul *= 10;
	}
}

/* Print a byte array in hexadecimal */
void byte_array_print(const uint8_t *buffer, const unsigned int length)
{
	for (unsigned int i = 0; i < length; i++)
		printf("%02x", buffer[i]);
}

#endif /* UTILS_H */
