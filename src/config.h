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
#ifndef CONFIG_H
#define CONFIG_H

#define ENDIANNESS_PORTABLE_CONVERSION
#include "endianness.h"

#define sha256(i, l, d) sha256_full(i, l, d)
#define hmac_sha256(k, l, i, n, o) \
	hmac_sha256_full(k, l, i, n, o)

#endif /* CONFIG_H */
