#ifndef AES_CBC_H
#define AES_CBC_H

int aes_128_cbc_decrypt(
        const unsigned char *key,
        const unsigned char *iv,
        unsigned char *data,
        size_t data_len);

#endif
