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
#ifndef WPS_H
#define WPS_H

/* WPS constants */
#define WPS_PIN_LEN           8
#define WPS_PKEY_LEN        192
#define WPS_HASH_LEN         32
#define WPS_AUTHKEY_LEN      32
#define WPS_EMSK_LEN         32
#define WPS_KEYWRAPKEY_LEN   16
#define WPS_NONCE_LEN        16
#define WPS_SECRET_NONCE_LEN 16
#define WPS_PSK_LEN          16
#define WPS_BSSID_LEN         6

#define ENC_SETTINGS_LEN    256 /* There is not a max length */
#define MAX_PSK_LEN          64

#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "pixiewps.h"
#include "utils.h"

struct ie_vtag {
	uint16_t id;
#define WPS_TAG_E_SNONCE_1   "\x10\x16"
#define WPS_TAG_E_SNONCE_2   "\x10\x17"
#define WPS_TAG_SSID         "\x10\x45"
#define WPS_TAG_BSSID        "\x10\x20"
#define WPS_TAG_AUTH_TYPE    "\x10\x03"
#define WPS_TAG_ENC_TYPE     "\x10\x0F"
#define WPS_TAG_NET_KEY      "\x10\x27"
#define WPS_TAG_NET_KEY_IDX  "\x10\x28"
#define WPS_TAG_KEYWRAP_AUTH "\x10\x1E"
	uint16_t len;
#define WPS_TAG_AUTH_TYPE_LEN    2
#define WPS_TAG_ENC_TYPE_LEN     2
#define WPS_TAG_NET_KEY_IDX_LEN  1
#define WPS_TAG_KEYWRAP_AUTH_LEN 8
	uint8_t data[];
} __attribute__((packed));
#define	VTAG_SIZE (sizeof(struct ie_vtag))

struct ie_vtag *find_vtag(void *vtagp, int vtagl, void *vidp, int vlen)
{
	uint8_t *vid = vidp;
	struct ie_vtag *vtag = vtagp;
	while (0 < vtagl) {
		const int len = end_ntoh16(vtag->len);
		if (vid && memcmp(vid, &vtag->id, 2) != 0)
			goto next_vtag;
		if (!vlen || len == vlen)
			return vtag;

next_vtag:
		vtagl -= len + VTAG_SIZE;
		vtag = (struct ie_vtag *)((uint8_t *)vtag + len + VTAG_SIZE);
	}
	return NULL;
}

/* Diffie-Hellman group */
static const uint8_t dh_group5_generator[1] = { 0x02 };
static const uint8_t dh_group5_prime[192] = {
	0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF, 0xC9,0x0F,0xDA,0xA2, 0x21,0x68,0xC2,0x34,
	0xC4,0xC6,0x62,0x8B, 0x80,0xDC,0x1C,0xD1, 0x29,0x02,0x4E,0x08, 0x8A,0x67,0xCC,0x74,
	0x02,0x0B,0xBE,0xA6, 0x3B,0x13,0x9B,0x22, 0x51,0x4A,0x08,0x79, 0x8E,0x34,0x04,0xDD,
	0xEF,0x95,0x19,0xB3, 0xCD,0x3A,0x43,0x1B, 0x30,0x2B,0x0A,0x6D, 0xF2,0x5F,0x14,0x37,
	0x4F,0xE1,0x35,0x6D, 0x6D,0x51,0xC2,0x45, 0xE4,0x85,0xB5,0x76, 0x62,0x5E,0x7E,0xC6,
	0xF4,0x4C,0x42,0xE9, 0xA6,0x37,0xED,0x6B, 0x0B,0xFF,0x5C,0xB6, 0xF4,0x06,0xB7,0xED,
	0xEE,0x38,0x6B,0xFB, 0x5A,0x89,0x9F,0xA5, 0xAE,0x9F,0x24,0x11, 0x7C,0x4B,0x1F,0xE6,
	0x49,0x28,0x66,0x51, 0xEC,0xE4,0x5B,0x3D, 0xC2,0x00,0x7C,0xB8, 0xA1,0x63,0xBF,0x05,
	0x98,0xDA,0x48,0x36, 0x1C,0x55,0xD3,0x9A, 0x69,0x16,0x3F,0xA8, 0xFD,0x24,0xCF,0x5F,
	0x83,0x65,0x5D,0x23, 0xDC,0xA3,0xAD,0x96, 0x1C,0x62,0xF3,0x56, 0x20,0x85,0x52,0xBB,
	0x9E,0xD5,0x29,0x07, 0x70,0x96,0x96,0x6D, 0x67,0x0C,0x35,0x4E, 0x4A,0xBC,0x98,0x04,
	0xF1,0x74,0x6C,0x08, 0xCA,0x23,0x73,0x27, 0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF
};

/* Wi-Fi Easy and Secure Key Derivation */
static const uint8_t kdf_salt[] = {
	0x57,0x69,0x2D,0x46, 0x69,0x20,0x45,0x61, 0x73,0x79,0x20,0x61, 0x6E,0x64,0x20,0x53,
	0x65,0x63,0x75,0x72, 0x65,0x20,0x4B,0x65, 0x79,0x20,0x44,0x65, 0x72,0x69,0x76,0x61,
	0x74,0x69,0x6F,0x6E
};

/* Key Derivation Function */
void kdf(const void *key, uint8_t *res)
{
	const uint32_t kdk_len = (WPS_AUTHKEY_LEN + WPS_KEYWRAPKEY_LEN + WPS_EMSK_LEN) * 8;
	uint_fast8_t j = 0;

	uint8_t *buffer = malloc(sizeof(kdf_salt) + sizeof(uint32_t) * 2);

	for (uint32_t i = 1; i < 4; i++) {
		uint32_t be = end_htobe32(i);
		memcpy(buffer, &be, sizeof(uint32_t));
		memcpy(buffer + sizeof(uint32_t), kdf_salt, sizeof(kdf_salt));
		be = end_htobe32(kdk_len);
		memcpy(buffer + sizeof(uint32_t) + sizeof(kdf_salt), &be, sizeof(uint32_t));
		hmac_sha256(key, WPS_HASH_LEN, buffer, sizeof(kdf_salt) + sizeof(uint32_t) * 2, res + j);
		j += WPS_HASH_LEN;
	}
	free(buffer);
}

/* Decrypt encrypted settings in M7-M8 */
uint8_t *decrypt_encr_settings(uint8_t *keywrapkey, const uint8_t *encr, size_t encr_len)
{
	uint8_t *decrypted;
	const size_t block_size = 16;
	size_t i;
	uint8_t pad;
	const uint8_t *pos;
	size_t n_encr_len;

	/* AES-128-CBC */
	if (encr == NULL || encr_len < 2 * block_size || encr_len % block_size)
		return NULL;

	decrypted = malloc(encr_len - block_size);
	if (decrypted == NULL)
		return NULL;

	memcpy(decrypted, encr + block_size, encr_len - block_size);
	n_encr_len = encr_len - block_size;
	if (aes_128_cbc_decrypt(keywrapkey, encr, decrypted, n_encr_len)) {
		free(decrypted);
		return NULL;
	}

	pos = decrypted + n_encr_len - 1;
	pad = *pos;
	if (pad > n_encr_len) {
		free(decrypted);
		return NULL;
	}
	for (i = 0; i < pad; i++) {
		if (*pos-- != pad) {
			free(decrypted);
			return NULL;
		}
	}

	return decrypted;
}

/* Pin checksum computing */
static inline uint_fast8_t wps_pin_checksum(uint_fast32_t pin)
{
	unsigned int acc = 0;
	while (pin) {
		acc += 3 * (pin % 10);
		pin /= 10;
		acc += pin % 10;
		pin /= 10;
	}
	return (10 - acc % 10) % 10;
}

/* Validity PIN control based on checksum */
static inline uint_fast8_t wps_pin_valid(uint_fast32_t pin)
{
	return wps_pin_checksum(pin / 10) == (pin % 10);
}

/* Checks if PKe == 2 */
static inline uint_fast8_t check_small_dh_keys(const uint8_t *data)
{
	uint_fast8_t i = WPS_PKEY_LEN - 2;
	while (--i) {
		if (data[i] != 0)
			break;
	}
	i = (i == 0 && data[WPS_PKEY_LEN - 1] == 0x02) ? 1 : 0;
	return i;
}

#endif /* WPS_H */
