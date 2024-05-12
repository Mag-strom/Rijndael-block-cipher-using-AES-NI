#include <stdio.h>
#include <wmmintrin.h>

  void KEY_256_ASSIST_1(__m128i* temp1, __m128i * temp2)
 {
 __m128i temp4;
 *temp2 = _mm_shuffle_epi32(*temp2, 0xff);
 temp4 = _mm_slli_si128 (*temp1, 0x4);
 *temp1 = _mm_xor_si128 (*temp1, temp4);
 temp4 = _mm_slli_si128 (temp4, 0x4);
 *temp1 = _mm_xor_si128 (*temp1, temp4);
 temp4 = _mm_slli_si128 (temp4, 0x4);
 *temp1 = _mm_xor_si128 (*temp1, temp4);
 *temp1 = _mm_xor_si128 (*temp1, *temp2);
 }
 void KEY_256_ASSIST_2(__m128i* temp1, __m128i * temp3)
 {
 __m128i temp2,temp4;
 temp4 = _mm_aeskeygenassist_si128 (*temp1, 0x0);
 temp2 = _mm_shuffle_epi32(temp4, 0xaa);
 temp4 = _mm_slli_si128 (*temp3, 0x4);
 *temp3 = _mm_xor_si128 (*temp3, temp4);
 temp4 = _mm_slli_si128 (temp4, 0x4);
 *temp3 = _mm_xor_si128 (*temp3, temp4);
 temp4 = _mm_slli_si128 (temp4, 0x4);
 *temp3 = _mm_xor_si128 (*temp3, temp4);
 *temp3 = _mm_xor_si128 (*temp3, temp2);
 } 

void AES_256_Key_Expansion (const unsigned char *userkey,
 unsigned char *key)
 {
 __m128i temp1, temp2, temp3;
 __m128i *Key_Schedule = (__m128i*)key;
 temp1 = _mm_loadu_si128((__m128i*)userkey);
 temp3 = _mm_loadu_si128((__m128i*)(userkey+16));
 Key_Schedule[0] = temp1;
 Key_Schedule[1] = temp3;
 temp2 = _mm_aeskeygenassist_si128 (temp3,0x01);
 KEY_256_ASSIST_1(&temp1, &temp2); 
 Key_Schedule[2]=temp1;
 KEY_256_ASSIST_2(&temp1, &temp3);
 Key_Schedule[3]=temp3;
 temp2 = _mm_aeskeygenassist_si128 (temp3,0x02);
 KEY_256_ASSIST_1(&temp1, &temp2);
 Key_Schedule[4]=temp1;
 KEY_256_ASSIST_2(&temp1, &temp3);
 Key_Schedule[5]=temp3;
 temp2 = _mm_aeskeygenassist_si128 (temp3,0x04);
 KEY_256_ASSIST_1(&temp1, &temp2);
 Key_Schedule[6]=temp1;
 KEY_256_ASSIST_2(&temp1, &temp3);
 Key_Schedule[7]=temp3;
 temp2 = _mm_aeskeygenassist_si128 (temp3,0x08);
 KEY_256_ASSIST_1(&temp1, &temp2);
 Key_Schedule[8]=temp1;
 KEY_256_ASSIST_2(&temp1, &temp3);
 Key_Schedule[9]=temp3;
 temp2 = _mm_aeskeygenassist_si128 (temp3,0x10);
 KEY_256_ASSIST_1(&temp1, &temp2);
 Key_Schedule[10]=temp1;
 KEY_256_ASSIST_2(&temp1, &temp3);
 Key_Schedule[11]=temp3;
 temp2 = _mm_aeskeygenassist_si128 (temp3,0x20);
 KEY_256_ASSIST_1(&temp1, &temp2);
 Key_Schedule[12]=temp1;
 KEY_256_ASSIST_2(&temp1, &temp3);
 Key_Schedule[13]=temp3;
 temp2 = _mm_aeskeygenassist_si128 (temp3,0x40);
 KEY_256_ASSIST_1(&temp1, &temp2);
 Key_Schedule[14]=temp1;
 KEY_256_ASSIST_2(&temp1, &temp3);
 Key_Schedule[15]=temp3;
 temp2 = _mm_aeskeygenassist_si128 (temp3,0x80);
 KEY_256_ASSIST_1(&temp1, &temp2);
 Key_Schedule[16]=temp1;
 KEY_256_ASSIST_2(&temp1, &temp3);
 Key_Schedule[17]=temp3;
 temp2 = _mm_aeskeygenassist_si128 (temp3,0x1b);
 KEY_256_ASSIST_1(&temp1, &temp2);
 Key_Schedule[18]=temp1;
 KEY_256_ASSIST_2(&temp1, &temp3);
 Key_Schedule[19]=temp3;
 temp2 = _mm_aeskeygenassist_si128 (temp3,0x36);
 KEY_256_ASSIST_1(&temp1, &temp2);
 Key_Schedule[20]=temp1;
 KEY_256_ASSIST_2(&temp1, &temp3);
 Key_Schedule[21]=temp3;
 temp2 = _mm_aeskeygenassist_si128 (temp3,0x6c);
 KEY_256_ASSIST_1(&temp1, &temp2);
 Key_Schedule[22]=temp1;
 KEY_256_ASSIST_2(&temp1, &temp3);
 Key_Schedule[23]=temp3;
 temp2 = _mm_aeskeygenassist_si128 (temp3,0xd8);
 KEY_256_ASSIST_1(&temp1, &temp2);
 Key_Schedule[24]=temp1;
 KEY_256_ASSIST_2(&temp1, &temp3);
 Key_Schedule[25]=temp3;
 temp2 = _mm_aeskeygenassist_si128 (temp3,0xab);
 KEY_256_ASSIST_1(&temp1, &temp2);
 Key_Schedule[26]=temp1;
 KEY_256_ASSIST_2(&temp1, &temp3);
 Key_Schedule[27]=temp3;
 temp2 = _mm_aeskeygenassist_si128 (temp3,0x4d);
 KEY_256_ASSIST_1(&temp1, &temp2);
 Key_Schedule[28]=temp1;
 KEY_256_ASSIST_2(&temp1, &temp3);
 Key_Schedule[29]=temp3;
 
 } 

int main() {
    unsigned char userkey[32] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x97, 0x33, 0x5d, 0x5f, 0x96, 0x6e, 0x31, 0x4d, 0x6a, 0xb5, 0xf8, 0xc0, 0xe4};
    unsigned char key[15 * 32]; // 13 round keys of 16 bytes each

    AES_256_Key_Expansion(userkey, key);
 printf("Expanded keys:\n");
    for (int i = 0; i < 15; ++i) {
        printf("Round %2d: ", i);
        for (int j = 0; j < 32; ++j) {
            printf("%02X ", key[i * 32 + j]);
        }
        printf("\n");
    }
    return 0;
}
