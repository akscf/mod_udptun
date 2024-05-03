/**
 * a simple stream cipher based on RC4
 *
 * (C)2021 aks
 * https://github.com/akscf/
 **/
#include "cipher.h"

void cipher_init(cipher_ctx_t *ctx, const char* key, size_t key_len) {
    int i = 0,j = 0, t=0 ;
    uint8_t *sbox_b = (void *) bf_s_box;

    /* rc4 */
    for(i = 0; i < 256; i++) {
        ctx->m[i] = i;
    }
    for (i = 0, j = 0; i < 256; ++i) {
        j = (j + ctx->m[i] + key[i % key_len]) % 256;
        t = ctx->m[i];
        ctx->m[i] = ctx->m[j];
        ctx->m[j] = t;
    }

    /* init s-boxes */
    for(i=0; i <= 3; i++) {
        memcpy((uint8_t *)ctx->s[i], (uint8_t *)bf_s_box[i], 1024);
    }

    ctx->x=0; ctx->y=0;
    cipher_update(ctx);
}

void cipher_update(cipher_ctx_t *ctx) {
    int idx, i, a, b;
    for(idx = 0; idx <= 3; idx++) {
        uint8_t *p = (uint8_t *)ctx->s[idx];
        for (i = 0; i < 1024; i++) {
    	    a = ctx->m[++ctx->x];
    	    ctx->y += a;
    	    ctx->m[ctx->x] = b = ctx->m[ctx->y];
    	    ctx->m[ctx->y] = a;
    	    p[i] ^= ctx->m[(uint8_t)(a + b)];
        }
    }
}

void cipher_encrypt(cipher_ctx_t *ctx, uint32_t packet_id, uint8_t *buffer, size_t len) {
    uint32_t *p = (void *)buffer;
    uint32_t *s = ctx->s[packet_id % 4];
    int i, sz = (len / sizeof(int));

    if(len % sizeof(int)) { sz--; }

    for(i = 0; i < sz; i++) {
        p[i] = p[i] ^ s[i % 256];
    }

}

void cipher_decrypt(cipher_ctx_t *ctx, uint32_t packet_id, uint8_t *buffer, size_t len) {
    uint32_t *p = (void *)buffer;
    uint32_t *s = ctx->s[packet_id % 4];
    int i, sz = (len / sizeof(int));

    if(len % sizeof(int)) { sz--; }

    for(i = 0; i < sz; i++) {
        p[i] = p[i] ^ s[i % 256];
    }

}
