/* Public domain hmac_sha256 implementation written by rofl0r for pixiewps */

#include <stdint.h>
#include <string.h>
#ifdef USE_OPENSSL
# include <openssl/sha.h>
#else
# include "tc/tomcrypt.h"
# define SHA256_CTX hash_state
# define SHA256_Init(x) do { sha256_init(x); } while(0)
# define SHA256_Update(x, y, z) sha256_process(x, y, z)
# define SHA256_Final(y, x) sha256_done(x, y)
#endif

#define PAD_SIZE  64
#define HASH_SIZE 32

static void sha256_full(const uint8_t *input, size_t ilen, uint8_t *output)
{
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, input, ilen);
	SHA256_Final(output, &ctx);
}

static void hmac_sha256_full(const uint8_t *key, size_t keylen,
	const uint8_t *input, size_t ilen, uint8_t *output)
{
	size_t i;
	uint8_t opad[PAD_SIZE], ipad[PAD_SIZE], hash[HASH_SIZE];
	SHA256_CTX ctx;

	memset(ipad, 0x36, PAD_SIZE);
	memset(opad, 0x5C, PAD_SIZE);

	if (keylen > PAD_SIZE) {

		SHA256_Init(&ctx);
		SHA256_Update(&ctx, key, keylen);
		SHA256_Final(hash, &ctx);

		for (i = 0; i < HASH_SIZE; i++) {
			ipad[i] ^= hash[i];
			opad[i] ^= hash[i];
		}

	} else for (i = 0; i < keylen; i++) {
		ipad[i] ^= key[i];
		opad[i] ^= key[i];
	}

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, ipad, PAD_SIZE);
	SHA256_Update(&ctx, input, ilen);
	SHA256_Final(hash, &ctx);

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, opad, PAD_SIZE);
	SHA256_Update(&ctx, hash, sizeof hash);

	SHA256_Final(output, &ctx);
}

struct hmac_ctx {
	SHA256_CTX ictx;
	SHA256_CTX octx;
};

static void hmac_sha256_init(struct hmac_ctx *hctx, const uint8_t *key,
	size_t keylen)
{
	size_t i;
	uint8_t opad[PAD_SIZE], ipad[PAD_SIZE], hash[HASH_SIZE];
	SHA256_CTX ctx;

	memset(ipad, 0x36, PAD_SIZE);
	memset(opad, 0x5C, PAD_SIZE);

	if (keylen > PAD_SIZE) {

		SHA256_Init(&ctx);
		SHA256_Update(&ctx, key, keylen);
		SHA256_Final(hash, &ctx);

		for (i = 0; i < HASH_SIZE; i++) {
			ipad[i] ^= hash[i];
			opad[i] ^= hash[i];
		}

	} else for (i = 0; i < keylen; i++) {
		ipad[i] ^= key[i];
		opad[i] ^= key[i];
	}

	SHA256_Init(&hctx->ictx);
	SHA256_Update(&hctx->ictx, ipad, PAD_SIZE);

	SHA256_Init(&hctx->octx);
	SHA256_Update(&hctx->octx, opad, PAD_SIZE);
}

static void hmac_sha256_yield(const struct hmac_ctx *hctx,
	const uint8_t *input, size_t ilen, uint8_t *output)
{
	SHA256_CTX ctx;
	uint8_t hash[HASH_SIZE];

	memcpy(&ctx, &hctx->ictx, sizeof(ctx));

	SHA256_Update(&ctx, input, ilen);
	SHA256_Final(hash, &ctx);

	memcpy(&ctx, &hctx->octx, sizeof(ctx));

	SHA256_Update(&ctx, hash, sizeof hash);
	SHA256_Final(output, &ctx);
}
