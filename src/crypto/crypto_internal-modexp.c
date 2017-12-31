#include <stdlib.h>
#include <stdint.h>

#include "tfm/tfm.h"

#define u8 uint8_t

int crypto_mod_exp(const u8 *base, size_t base_len,
		   const u8 *power, size_t power_len,
		   const u8 *modulus, size_t modulus_len,
		   u8 *result, size_t *result_len)
{
	fp_int bn_base, bn_exp, bn_modulus, bn_result;

	fp_read_unsigned_bin(&bn_base, base, base_len);
	fp_read_unsigned_bin(&bn_exp, power, power_len);
	fp_read_unsigned_bin(&bn_modulus, modulus, modulus_len);
	fp_init(&bn_result);

	fp_exptmod(&bn_base, &bn_exp, &bn_modulus, &bn_result);

	fp_to_unsigned_bin(&bn_result, result);

	*result_len = fp_unsigned_bin_size(&bn_result);
	return 0;
}
