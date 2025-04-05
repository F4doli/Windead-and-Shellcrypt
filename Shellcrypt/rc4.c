#include "rc4.h"

// The function to initialize the context
void rc4Init(Rc4Context* context, const unsigned char* key, size_t length) {
    unsigned int i, j;
    unsigned char temp;

    if (context == NULL || key == NULL) {
        return;
    }

    context->i = 0;
    context->j = 0;

    for (i = 0; i < 256; i++) {
        context->s[i] = i;
    }

    for (i = 0, j = 0; i < 256; i++) {
        j = (j + context->s[i] + key[i % length]) % 256;
        temp = context->s[i];
        context->s[i] = context->s[j];
        context->s[j] = temp;
    }
}

// The function that does the encryption
void rc4Cipher(Rc4Context* context, const unsigned char* input, unsigned char* output, size_t length) {
    unsigned char temp;
    unsigned int i = context->i;
    unsigned int j = context->j;
    unsigned char* s = context->s;

    while (length > 0) {
        i = (i + 1) % 256;
        j = (j + s[i]) % 256;
        temp = s[i];
        s[i] = s[j];
        s[j] = temp;

        if (input != NULL && output != NULL) {
            *output = *input ^ s[(s[i] + s[j]) % 256];
            input++;
            output++;
        }
        length--;
    }

    context->i = i;
    context->j = j;
}