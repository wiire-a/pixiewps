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

#include <stdint.h>

#define ENDIANNESS_PORTABLE_CONVERSION
#include "endianness.h"

typedef unsigned char uint8_t;

#include "mbedtls/md_internal.h"
#include "mbedtls/sha256.h"

#define sha256(i, l, d) mbedtls_sha256(i, l, d, 0)
#define hmac_sha256(k, l, i, n, o) \
	mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), k, l, i, n, o)

#define u8  uint8_t
#define u16	uint16_t
#define u32	uint32_t
#define u64	uint64_t
#define os_memcpy memcpy
#define os_malloc malloc
#define os_memset memset
#define os_free   free

#endif /* CONFIG_H */
