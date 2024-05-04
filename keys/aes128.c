#include <stdint.h>     //for int8_t
#include <string.h>     //for memcmp
#include <wmmintrin.h>
#include <stdio.h>  //for intrinsics for AES-NI

#define AES_128_key_exp(k, rcon) aes_128_key_expansion(k, _mm_aeskeygenassist_si128(k, rcon))

static __m128i key_schedule[30];//the expanded key

static __m128i aes_128_key_expansion(__m128i key, __m128i keygened){
	keygened = _mm_shuffle_epi32(keygened, _MM_SHUFFLE(3,3,3,3));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	return _mm_xor_si128(key, keygened);
}

//public API
void aes128_load_key(int8_t *enc_key){
    key_schedule[0] = _mm_loadu_si128((const __m128i*) enc_key);
	key_schedule[1]  = AES_128_key_exp(key_schedule[0], 0x01);
	key_schedule[2]  = AES_128_key_exp(key_schedule[1], 0x02);
	key_schedule[3]  = AES_128_key_exp(key_schedule[2], 0x04);
	key_schedule[4]  = AES_128_key_exp(key_schedule[3], 0x08);
	key_schedule[5]  = AES_128_key_exp(key_schedule[4], 0x10);
	key_schedule[6]  = AES_128_key_exp(key_schedule[5], 0x20);
	key_schedule[7]  = AES_128_key_exp(key_schedule[6], 0x40);
	key_schedule[8]  = AES_128_key_exp(key_schedule[7], 0x80);
	key_schedule[9]  = AES_128_key_exp(key_schedule[8], 0x1B);
	key_schedule[10] = AES_128_key_exp(key_schedule[9], 0x36);
	key_schedule[11] = AES_128_key_exp(key_schedule[10], 0x6c);
	key_schedule[12] = AES_128_key_exp(key_schedule[11], 0xd8);
	key_schedule[13] = AES_128_key_exp(key_schedule[12], 0xab);
	key_schedule[14] = AES_128_key_exp(key_schedule[13], 0x4d);
	key_schedule[15] = AES_128_key_exp(key_schedule[14], 0x9a);
	key_schedule[16] = AES_128_key_exp(key_schedule[15], 0x2f);
	key_schedule[17] = AES_128_key_exp(key_schedule[16], 0x5e);
	key_schedule[18] = AES_128_key_exp(key_schedule[17], 0xbc);
	key_schedule[19] = AES_128_key_exp(key_schedule[18],0x63);
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

void print_key_schedule() {
    for (int i = 0; i < 30; i++) {
        printf("Round %2d: ", i);
        for (int j = 0; j < 16; j++) {
            printf("%02x ", ((uint8_t*)&key_schedule[i])[j]);
        }
        printf("\n");
    }
}


int main(){
 int8_t enc_key[]    = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
 aes128_load_key(enc_key);
print_key_schedule();
 return 0;
}


