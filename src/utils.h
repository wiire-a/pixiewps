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
#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Converts an hex string to a byte array */
unsigned int hex_string_to_byte_array(char *in, uint8_t *out, const unsigned int n_len) {
	uint_fast8_t o;
	unsigned int len = strlen(in);
	unsigned int b_len = n_len * 2 + n_len - 1;

	if (len != n_len * 2 && len != b_len)
		return 1;
	for (unsigned int i = 0; i < n_len; i++) {
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
		};
		*out++ = o;
		if (len == b_len) {
			if (*in == ':' || *in == '-' || *in == ' ' || *in == 0)
				in++;
			else 
				return 1;
		}
	}
	return 0;
};

/* Converts a string into an integer */
int get_int(char *in, int *out) {
	int i, o = 0, len = strlen(in);
	for (i = 0; i < len; i++) {
		if ('0' <= *in && *in <= '9')
			o = o * 10 + *in - '0';
		else
			return 1;
		in++;
	};
	*out = o;
	return 0;
};

/* Converts a [mm/]yyyy string to Unix date time */
unsigned int get_unix_datetime(char *s, time_t *datetime) {
	unsigned int len = strlen(s);
	int month = 0, year;
	struct tm tm;

	if (len == 4) {
		if (get_int(s, &year))
			return 1;
	} else if (len == 7) {
		if (s[2] != '/' && s[2] != '-' && s[2] != '.')
			return 1;

		char s_month[3];
		char s_year[5];
		if (s[0] == '0') {
			s_month[0] = s[1];
			s_month[1] = 0;
		} else {
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
	} else {
		return 1;
	}

	tm.tm_sec = 0;
	tm.tm_min = 0;
	tm.tm_hour = 0;
	tm.tm_mday = 1;
	tm.tm_mon = month - 1;
	tm.tm_year = year - 1900;
	tm.tm_isdst = -1;
	*datetime = mktime(&tm);

	if (*datetime < 0)
		return 1;

	return 0;
}

/* Converts an unsigned integer to a char array without termination */
inline void uint_to_char_array(unsigned int num, unsigned int len, uint8_t *dst) {
	unsigned int mul = 1;
	while (len--) {
		dst[len] = (num % (mul * 10) / mul) + '0';
		mul *= 10;
	}
}

/* Prints a byte array in hexadecimal */
void byte_array_print(const uint8_t *buffer, const unsigned int length) {
	unsigned int i;
	for (i = 0; i < length; i++) {
		printf("%02x", buffer[i]);
		if (i != length - 1)
			printf(":");
	}
}

/* Converts a 32 Little Endian bit number to its Big Endian representation */
uint32_t h32_to_be(const uint32_t num) {
	uint32_t tmp = num;
	uint32_t res;
	uint32_t b0, b1, b2, b3;
	unsigned int i = 1;
	char *p = (char *) &i;

	if (p[0] == 1) { /* LE */
		b0 = (tmp & 0x000000ff) << 24;
		b1 = (tmp & 0x0000ff00) << 8;
		b2 = (tmp & 0x00ff0000) >> 8;
		b3 = (tmp & 0xff000000) >> 24;
		res = b0 | b1 | b2 | b3;
	} else {         /* BE */
		res = num;
	}
	return res;
}

#endif /* UTILS_H */
