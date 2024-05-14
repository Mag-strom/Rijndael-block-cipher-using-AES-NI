#include <stdint.h> //for int8_t
#include <string.h> //for memcmp
#include <wmmintrin.h>
#include <tmmintrin.h>
#include <smmintrin.h>
#include <time.h>
#include <stdio.h> //for intrinsics for AES-NI
void print128(__m128i var)
{
    unsigned char *val = (unsigned char *)&var;
    printf("%02X %02X %02X %02X  %02X %02X %02X %02X  %02X %02X %02X %02X  %02X %02X %02X %02X \n",
           val[0], val[1], val[2], val[3], val[4], val[5], val[6], val[7],
           val[8], val[9], val[10], val[11], val[12], val[13], val[14], val[15]);
}

#define AES_128_key_exp(k, rcon) aes_128_key_expansion(k, _mm_aeskeygenassist_si128(k, rcon))



static __m128i aes_128_key_expansion(__m128i temp1, __m128i temp2){
	__m128i temp3;
 temp2 = _mm_shuffle_epi32 (temp2 ,0xff);
 temp3 = _mm_slli_si128 (temp1, 0x4);
 temp1 = _mm_xor_si128 (temp1, temp3);
 temp3 = _mm_slli_si128 (temp3, 0x4);
 temp1 = _mm_xor_si128 (temp1, temp3);
 temp3 = _mm_slli_si128 (temp3, 0x4);
 temp1 = _mm_xor_si128 (temp1, temp3);
 temp1 = _mm_xor_si128 (temp1, temp2);
 return temp1; 
}

// public API
void aes128_load_key(int8_t *enc_key, unsigned char *key)
{
    __m128i *key_schedule = (__m128i *)key;
    key_schedule[0] = _mm_loadu_si128((const __m128i *)enc_key);
    key_schedule[1] = AES_128_key_exp(key_schedule[0], 0x01);
    key_schedule[2] = AES_128_key_exp(key_schedule[1], 0x02);
    key_schedule[3] = AES_128_key_exp(key_schedule[2], 0x04);
    key_schedule[4] = AES_128_key_exp(key_schedule[3], 0x08);
    key_schedule[5] = AES_128_key_exp(key_schedule[4], 0x10);
    key_schedule[6] = AES_128_key_exp(key_schedule[5], 0x20);
    key_schedule[7] = AES_128_key_exp(key_schedule[6], 0x40);
    key_schedule[8] = AES_128_key_exp(key_schedule[7], 0x80);
    key_schedule[9] = AES_128_key_exp(key_schedule[8], 0x1B);
    key_schedule[10] = AES_128_key_exp(key_schedule[9], 0x36);
    key_schedule[11] = AES_128_key_exp(key_schedule[10], 0x6c);
    key_schedule[12] = AES_128_key_exp(key_schedule[11], 0xd8);
    key_schedule[13] = AES_128_key_exp(key_schedule[12], 0xab);
    key_schedule[14] = AES_128_key_exp(key_schedule[13], 0x4d);
    key_schedule[15] = AES_128_key_exp(key_schedule[14], 0x9a);
    key_schedule[16] = AES_128_key_exp(key_schedule[15], 0x2f);
    key_schedule[17] = AES_128_key_exp(key_schedule[16], 0x5e);
    key_schedule[18] = AES_128_key_exp(key_schedule[17], 0xbc);
    key_schedule[19] = AES_128_key_exp(key_schedule[18], 0x63);
    key_schedule[20] = AES_128_key_exp(key_schedule[19], 0xc6);
    key_schedule[21] = AES_128_key_exp(key_schedule[20], 0x97);
    key_schedule[22] = AES_128_key_exp(key_schedule[21], 0x35);
    key_schedule[23] = AES_128_key_exp(key_schedule[22], 0x6a);
    key_schedule[24] = AES_128_key_exp(key_schedule[23], 0xd4);

    key_schedule[25] = AES_128_key_exp(key_schedule[24], 0xb3);
    key_schedule[26] = AES_128_key_exp(key_schedule[25], 0x7d);
    key_schedule[27] = AES_128_key_exp(key_schedule[26], 0xfa);
    key_schedule[28] = AES_128_key_exp(key_schedule[27], 0xef);
    key_schedule[29] = AES_128_key_exp(key_schedule[28], 0xc5);

}

void Rijndael256_encrypt(unsigned char *in,
                         unsigned char *out,
                         unsigned char *key,
                         long long length,
                         int number_of_rounds)
{

    __m128i tmp1, tmp2, data1, data2;
    __m128i RIJNDAEL256_MASK =
        _mm_set_epi32(0x03020d0c, 0x0f0e0908, 0x0b0a0504, 0x07060100);
    __m128i BLEND_MASK =
        _mm_set_epi32(0x80000000, 0x80800000, 0x80800000, 0x80808000);

    __m128i keys[30];

    for (int i = 0; i < 30; i++)
    {
        keys[i] = _mm_loadu_si128((__m128i *)(key + (i) * 16));
    }

    int j, i;
    for (i = 0; i < length / 32; i++)
    {
        data1 = _mm_loadu_si128(&((__m128i *)in)[i*2+0]); /* load data block */
        data2 = _mm_loadu_si128(&((__m128i *)in)[i*2+1]);

        data1 = _mm_xor_si128(data1, keys[0]); /* round 0 (initial xor) */
        data2 = _mm_xor_si128(data2, keys[1]);

        for (j = 1; j < number_of_rounds; j++)
        {
            /*Blend to compensate for the shift rows shifts bytes between two
            128 bit blocks*/
            tmp1 = _mm_blendv_epi8(data1, data2, BLEND_MASK);
            tmp2 = _mm_blendv_epi8(data2, data1, BLEND_MASK);
            /*Shuffle that compensates for the additional shift in rows 3 and 4
            as opposed to rijndael128 (AES)*/
            tmp1 = _mm_shuffle_epi8(tmp1, RIJNDAEL256_MASK);
            tmp2 = _mm_shuffle_epi8(tmp2, RIJNDAEL256_MASK);
            /*This is the encryption step that includes sub bytes, shift rows,
            mix columns, xor with round key*/
            data1 = _mm_aesenc_si128(tmp1, keys[j * 2]);
            data2 = _mm_aesenc_si128(tmp2, keys[j * 2 + 1]);
        }
        tmp1 = _mm_blendv_epi8(data1, data2, BLEND_MASK);
        tmp2 = _mm_blendv_epi8(data2, data1, BLEND_MASK);
        tmp1 = _mm_shuffle_epi8(tmp1, RIJNDAEL256_MASK);
        tmp2 = _mm_shuffle_epi8(tmp2, RIJNDAEL256_MASK);
        tmp1 = _mm_aesenclast_si128(tmp1, keys[j * 2 + 0]); /*last AES round */
        tmp2 = _mm_aesenclast_si128(tmp2, keys[j * 2 + 1]);

        _mm_storeu_si128(&((__m128i *)out)[i * 2 + 0], tmp1);
        _mm_storeu_si128(&((__m128i *)out)[i * 2 + 1], tmp2);
    }
}


void Rijndael256_decrypt(unsigned char *in,
                         unsigned char *out,
                         unsigned char *key,
                         long long length,
                         int number_of_rounds)
{

    __m128i tmp1, tmp2, data1, data2;
    __m128i RIJNDAEL256_MASK =
        _mm_set_epi32(0x0b0a0d0c, 0x07060908, 0x03020504, 0x0f0e0100);
    __m128i BLEND_MASK =
        _mm_set_epi32(0x80808000, 0x80800000, 0x80800000, 0x80000000);

    __m128i keys[30];

    for (int i = 29; i >= 0; i--)
    {
        keys[29 - i] = _mm_loadu_si128((__m128i *)(key + (i) * 16));
    }

    int i, j;
    for (i = 0; i < length / 32; i++)
    {
        data1 = _mm_loadu_si128(&((__m128i *)in)[i * 2 + 0]); /* load data block */
        data2 = _mm_loadu_si128(&((__m128i *)in)[i * 2 + 1]);

        data1 = _mm_xor_si128(data1, keys[1]); /* round 0 (initial xor) */
        data2 = _mm_xor_si128(data2, keys[0]);

        for (j = 1; j < number_of_rounds; j++)
        {
            /*Blend to compensate for the shift rows shifts bytes between two
            128 bit blocks*/
            tmp1 = _mm_blendv_epi8(data1, data2, BLEND_MASK);
            tmp2 = _mm_blendv_epi8(data2, data1, BLEND_MASK);
            /*Shuffle that compensates for the additional shift in rows 3 and 4
            as opposed to rijndael128 (AES)*/
            tmp1 = _mm_shuffle_epi8(tmp1, RIJNDAEL256_MASK);
            tmp2 = _mm_shuffle_epi8(tmp2, RIJNDAEL256_MASK);
            /*This is the encryption step that includes sub bytes, shift rows,
            mix columns, xor with round key*/
            data1 = _mm_aesdec_si128(tmp1, _mm_aesimc_si128(keys[j * 2 + 1]));
            data2 = _mm_aesdec_si128(tmp2, _mm_aesimc_si128(keys[j * 2]));
        }
        tmp1 = _mm_blendv_epi8(data1, data2, BLEND_MASK);
        tmp2 = _mm_blendv_epi8(data2, data1, BLEND_MASK);
        tmp1 = _mm_shuffle_epi8(tmp1, RIJNDAEL256_MASK);
        tmp2 = _mm_shuffle_epi8(tmp2, RIJNDAEL256_MASK);
        tmp1 = _mm_aesdeclast_si128(tmp1, keys[j * 2 + 1]); /*last AES round */
        tmp2 = _mm_aesdeclast_si128(tmp2, keys[j * 2 + 0]);

        _mm_storeu_si128(&((__m128i *)out)[i * 2 + 0], tmp1);
        _mm_storeu_si128(&((__m128i *)out)[i * 2 + 1], tmp2);
    }
}

int main()
{
    int8_t enc_key[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    unsigned char key[480];
    unsigned char plain[3200] = {};
    unsigned char computed_cipher[3200] = {};
    unsigned char decrypt_cipher[3200];
    aes128_load_key(enc_key, key);


    printf("Enter plain Text\n");
    scanf("%[^\n]%*c", plain);
    printf("%ld\n",sizeof(plain));
    Rijndael256_encrypt(plain, computed_cipher, key, sizeof(plain), 14);
    
double sum_dec;
    for(int i=0;i<10;i++)
    {
    clock_t t;
     t=clock();  
    Rijndael256_decrypt(computed_cipher, decrypt_cipher, key, sizeof(computed_cipher), 14);
   t=clock()-t;
 double time_taken = ((double)t)/CLOCKS_PER_SEC;
 sum_dec+=time_taken;
    }
 printf("\ntime taken for Rijndeal 256 decryption is %f\n",sum_dec/10);
    // for (int i = 0; i < 16; i++)
    // {
    //     printf("%02x ", computed_cipher[i]);
    // }
    // printf("\n");
    // for (int i = 16; i < 32; i++)
    // {
    //     printf("%02x ", computed_cipher[i]);
    // }
    // printf("\n");
    // for (int i = 0; i < 16; i++)
    // {
    //     printf("%02x ", decrypt_cipher[i]);
    // }
    // printf("\n");
    // for (int i = 16; i < 32; i++)
    // {
    //     printf("%02x ", decrypt_cipher[i]);
    // }
    // printf("\n");
   
 printf("\n");
    // Printing the next 16 bytes as characters
    for (int i =0; i < sizeof(decrypt_cipher); i++)
    {
        printf("%c", (char)decrypt_cipher[i]);
    }
    printf("\n");

    return 0;
}
