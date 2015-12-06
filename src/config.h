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
#ifndef CONFIG_H
#define CONFIG_H

#if __STDC_VERSION__ < 199901L
# define inline static
#endif

#include <stdint.h>

typedef unsigned char uint8_t;

#include "crypto/md_internal.h"
#include "crypto/sha256.h"

#define sha256(i, l, d) mbedtls_sha256(i, l, d, 0)
#define hmac_sha256(k, l, i, n, o) \
	mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), k, l, i, n, o)

#endif /* CONFIG_H */
