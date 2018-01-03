/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */
#include "tomcrypt.h"

#undef LTC_ARGCHK
#define LTC_ARGCHK(X) do {} while(0)

/**
   @file cbc_start.c
   CBC implementation, start chain, Tom St Denis
*/

/**
   Initialize a CBC context
   @param cipher      The index of the cipher desired
   @param IV          The initialization vector
   @param key         The secret key
   @param keylen      The length of the secret key (octets)
   @param num_rounds  Number of rounds in the cipher desired (0 for default)
   @param cbc         The CBC state to initialize
   @return CRYPT_OK if successful
*/
static int pixie_cbc_start(const unsigned char *IV, const unsigned char *key,
              int keylen, int num_rounds, symmetric_CBC *cbc)
{
   int x, err;

   LTC_ARGCHK(IV != NULL);
   LTC_ARGCHK(key != NULL);
   LTC_ARGCHK(cbc != NULL);

   /* setup cipher */
   if ((err = rijndael_setup(key, keylen, num_rounds, &cbc->key)) != CRYPT_OK) {
      return err;
   }

   /* copy IV */
   cbc->blocklen = 16;
   for (x = 0; x < cbc->blocklen; x++) {
       cbc->IV[x] = IV[x];
   }
   return CRYPT_OK;
}


/**
  CBC decrypt
  @param ct     Ciphertext
  @param pt     [out] Plaintext
  @param len    The number of bytes to process (must be multiple of block length)
  @param cbc    CBC state
  @return CRYPT_OK if successful
*/
static int pixie_cbc_decrypt(const unsigned char *ct, unsigned char *pt, unsigned long len, symmetric_CBC *cbc)
{
   int x, err;
   unsigned char tmp[16];
   unsigned char tmpy;

   LTC_ARGCHK(pt  != NULL);
   LTC_ARGCHK(ct  != NULL);
   LTC_ARGCHK(cbc != NULL);

   /* is blocklen valid? */
   if (cbc->blocklen < 1 || cbc->blocklen > (int)sizeof(cbc->IV) || cbc->blocklen > (int)sizeof(tmp)) {
      return CRYPT_INVALID_ARG;
   }

   if (len % cbc->blocklen) {
      return CRYPT_INVALID_ARG;
   }

   if (0) { /*cipher_descriptor[cbc->cipher].accel_cbc_decrypt != NULL) {
      return cipher_descriptor[cbc->cipher].accel_cbc_decrypt(ct, pt, len / cbc->blocklen, cbc->IV, &cbc->key);
	*/
   } else {
      while (len) {
         /* decrypt */
         if ((err = rijndael_ecb_decrypt(ct, tmp, &cbc->key)) != CRYPT_OK) {
            return err;
         }

         /* xor IV against plaintext */
         for (x = 0; x < cbc->blocklen; x++) {
            tmpy       = tmp[x] ^ cbc->IV[x];
            cbc->IV[x] = ct[x];
            pt[x]      = tmpy;
         }

         ct  += cbc->blocklen;
         pt  += cbc->blocklen;
         len -= cbc->blocklen;
      }
   }
   return CRYPT_OK;
}


/**
 * aes_128_cbc_decrypt - AES-128 CBC decryption
 * @key: Decryption key
 * @iv: Decryption IV for CBC mode (16 bytes)
 * @data: Data to decrypt in-place
 * @data_len: Length of data in bytes (must be divisible by 16)
 * Returns: 0 on success, -1 on failure
 */
int aes_128_cbc_decrypt(
	const unsigned char *key,
	const unsigned char *iv,
	unsigned char *data,
	size_t data_len)
{
	symmetric_CBC ctx;
	int ret = pixie_cbc_start(iv, key, 16, 0, &ctx);
	if(ret != CRYPT_OK) return -1;
	while(data_len) {
		unsigned char tmp[16];
		size_t left = data_len >= 16 ? 16 : data_len;
		ret = pixie_cbc_decrypt(data, tmp, left, &ctx);
		if(ret != CRYPT_OK) return -1;
		memcpy(data, tmp, left);
		data += left;
		data_len -= left;
	}
	rijndael_done(&ctx.key);
	return 0;
}
