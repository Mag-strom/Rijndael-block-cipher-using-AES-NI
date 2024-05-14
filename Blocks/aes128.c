#include <stdint.h>     //for int8_t
#include <string.h>     //for memcmp
#include <wmmintrin.h>
#include <stdio.h>  //for intrinsics for AES-NI
#include <time.h>
#define AES_128_key_exp(k, rcon) aes_128_key_expansion(k, _mm_aeskeygenassist_si128(k, rcon))

static __m128i key_schedule[30];//the expanded key

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
void print128(__m128i var)
{
    unsigned char *val = (unsigned char *)&var;
    printf("%02X %02X %02X %02X  %02X %02X %02X %02X  %02X %02X %02X %02X  %02X %02X %02X %02X \n",
           val[0], val[1], val[2], val[3], val[4], val[5], val[6], val[7],
           val[8], val[9], val[10], val[11], val[12], val[13], val[14], val[15]);
}
void AES_ECB_encrypt(const unsigned char *in, //pointer to the PLAINTEXT
 unsigned char *out, //pointer to the CIPHERTEXT buffer
  //text length in bytes
 unsigned char *key,
 unsigned long length, //pointer to the expanded key schedule
 int number_of_rounds) //number of AES rounds 10,12 or 14
 {
 __m128i tmp;
 int j,i;

	
for (i = 0; i < length / 16; i++)
    {

	tmp = _mm_loadu_si128 (&((__m128i*)in)[i]);
 tmp = _mm_xor_si128 (tmp,key_schedule[0]);
 for(j=1; j <number_of_rounds; j++){
 tmp = _mm_aesenc_si128 (tmp,key_schedule[j]);
 }
 tmp = _mm_aesenclast_si128 (tmp,key_schedule[j]);
 _mm_storeu_si128 (&((__m128i*)out)[i],tmp);
 }
 } 

 
 void AES_ECB_decrypt(const unsigned char *in, //pointer to the CIPHERTEXT
 unsigned char *out, //pointer to the DECRYPTED TEXT buffer
  //text length in bytes
 unsigned char *key,
 unsigned long length, //pointer to the expanded key schedule
 int number_of_rounds) //number of AES rounds 10,12 or 14
 {
 __m128i tmp;
 int j=0,i;

for (i = 0; i < length / 16; i++)
    {
 tmp = _mm_loadu_si128 (&((__m128i*)in)[i]);
 tmp = _mm_xor_si128 (tmp,key_schedule[10-j]);
 for(j=1; j <10; j++){
 tmp = _mm_aesdec_si128 (tmp,_mm_aesimc_si128((key_schedule[10-j])));
 }
 tmp = _mm_aesdeclast_si128 (tmp,key_schedule[j]);
 _mm_storeu_si128 (&((__m128i*)out)[i],tmp);
 }
 } 
//public API
void aes128_load_key(int8_t *enc_key, unsigned char *key){
	 __m128i *key_schedule = (__m128i *)key;
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
 
unsigned char key[480];aes128_load_key(enc_key,key);
unsigned char plain[3200] = {};
unsigned char computed_cipher[3200] = {};
unsigned char decrypt_cipher[3200];
 printf("Enter plain Text\n");
    scanf("%[^\n]%*c", plain);
    printf("%ld\n",sizeof(plain));
    AES_ECB_encrypt(plain, computed_cipher, key,sizeof(plain), 10);
	
	double sum_dec;
	for(int i=0;i<10;i++)
	{
	clock_t t;
     t=clock(); 
    AES_ECB_decrypt(computed_cipher, decrypt_cipher, key,sizeof(computed_cipher), 10);
  t=clock()-t;
 double time_taken = ((double)t)/CLOCKS_PER_SEC;
 sum_dec+=time_taken;
	}
 printf("\ntime taken for AES-128 decryption is %f\n\n",sum_dec/10);
 for (int i =0; i < sizeof(decrypt_cipher); i++)
    {
        printf("%c", (char)decrypt_cipher[i]);
    }
    printf("\n");
 return 0;
}


