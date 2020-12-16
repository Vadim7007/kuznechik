/*
Реализация алгоритма шифрования "Кузнечик" (ГОСТ 34.12—2015)
Данный алгоритм реализован для использования этого шифрования в 
файловой системе OpenZFS, (проект с открытым исходным кодом)
https://github.com/openzfs/zfs
Реализован режим простой замены
Шифруются блоки по 128 бит
Шифрование подменяется в исходном коде
Алгоритм может использовать свои собственные ключи шифрования,
если из ввести, но это неэффективно, т.к. для всех блоков 
будут использоваться одиннаковые ключи
Алгоритм принимает ключи стандартного шифрования системы 
(они были предназначены для шифрования AES) размером 128 бит
*/

#include <stdint.h>
#include <string.h>
#include <malloc.h>

#include "stdfix.h"  //Необходимо скачать текст отдельно и создать файл

#define DEBUG_MODE
#define BLOCK_SIZE 16// Размер блока 16 байт (или 128 бит)

#ifdef DEBUG_MODE
static void
GOST_Kuz_PrintDebug(uint8_t* state)
{
    int i;
    for (i = 0; i < BLOCK_SIZE; i++)
        printf("%02x", state[i]);
    printf("\n");
}
#endif

typedef uint8_t vect[BLOCK_SIZE]; //блок размером 128 бит

/*
значения для нелинейного преобразования
множества двоичных векторов(преобразование S)
*/
static const unsigned char Pi[256] = {
    0xFC, 0xEE, 0xDD, 0x11, 0xCF, 0x6E, 0x31, 0x16,
    0xFB, 0xC4, 0xFA, 0xDA, 0x23, 0xC5, 0x04, 0x4D,
    0xE9, 0x77, 0xF0, 0xDB, 0x93, 0x2E, 0x99, 0xBA,
    0x17, 0x36, 0xF1, 0xBB, 0x14, 0xCD, 0x5F, 0xC1,
    0xF9, 0x18, 0x65, 0x5A, 0xE2, 0x5C, 0xEF, 0x21,
    0x81, 0x1C, 0x3C, 0x42, 0x8B, 0x01, 0x8E, 0x4F,
    0x05, 0x84, 0x02, 0xAE, 0xE3, 0x6A, 0x8F, 0xA0,
    0x06, 0x0B, 0xED, 0x98, 0x7F, 0xD4, 0xD3, 0x1F,
    0xEB, 0x34, 0x2C, 0x51, 0xEA, 0xC8, 0x48, 0xAB,
    0xF2, 0x2A, 0x68, 0xA2, 0xFD, 0x3A, 0xCE, 0xCC,
    0xB5, 0x70, 0x0E, 0x56, 0x08, 0x0C, 0x76, 0x12,
    0xBF, 0x72, 0x13, 0x47, 0x9C, 0xB7, 0x5D, 0x87,
    0x15, 0xA1, 0x96, 0x29, 0x10, 0x7B, 0x9A, 0xC7,
    0xF3, 0x91, 0x78, 0x6F, 0x9D, 0x9E, 0xB2, 0xB1,
    0x32, 0x75, 0x19, 0x3D, 0xFF, 0x35, 0x8A, 0x7E,
    0x6D, 0x54, 0xC6, 0x80, 0xC3, 0xBD, 0x0D, 0x57,
    0xDF, 0xF5, 0x24, 0xA9, 0x3E, 0xA8, 0x43, 0xC9,
    0xD7, 0x79, 0xD6, 0xF6, 0x7C, 0x22, 0xB9, 0x03,
    0xE0, 0x0F, 0xEC, 0xDE, 0x7A, 0x94, 0xB0, 0xBC,
    0xDC, 0xE8, 0x28, 0x50, 0x4E, 0x33, 0x0A, 0x4A,
    0xA7, 0x97, 0x60, 0x73, 0x1E, 0x00, 0x62, 0x44,
    0x1A, 0xB8, 0x38, 0x82, 0x64, 0x9F, 0x26, 0x41,
    0xAD, 0x45, 0x46, 0x92, 0x27, 0x5E, 0x55, 0x2F,
    0x8C, 0xA3, 0xA5, 0x7D, 0x69, 0xD5, 0x95, 0x3B,
    0x07, 0x58, 0xB3, 0x40, 0x86, 0xAC, 0x1D, 0xF7,
    0x30, 0x37, 0x6B, 0xE4, 0x88, 0xD9, 0xE7, 0x89,
    0xE1, 0x1B, 0x83, 0x49, 0x4C, 0x3F, 0xF8, 0xFE,
    0x8D, 0x53, 0xAA, 0x90, 0xCA, 0xD8, 0x85, 0x61,
    0x20, 0x71, 0x67, 0xA4, 0x2D, 0x2B, 0x09, 0x5B,
    0xCB, 0x9B, 0x25, 0xD0, 0xBE, 0xE5, 0x6C, 0x52,
    0x59, 0xA6, 0x74, 0xD2, 0xE6, 0xF4, 0xB4, 0xC0,
    0xD1, 0x66, 0xAF, 0xC2, 0x39, 0x4B, 0x63, 0xB6
};

//Нелинейное биективное преобразование (преобразование S) 
static void
GOST_Kuz_S(const uint8_t* in_data, uint8_t* out_data)
{
    int i;
    for (i = 0; i < BLOCK_SIZE; i++)
        out_data[i] = Pi[in_data[i]];
}

//массив обратного преобразования S
static const unsigned char reverse_Pi[256] = {
    0xA5, 0x2D, 0x32, 0x8F, 0x0E, 0x30, 0x38, 0xC0,
    0x54, 0xE6, 0x9E, 0x39, 0x55, 0x7E, 0x52, 0x91,
    0x64, 0x03, 0x57, 0x5A, 0x1C, 0x60, 0x07, 0x18,
    0x21, 0x72, 0xA8, 0xD1, 0x29, 0xC6, 0xA4, 0x3F,
    0xE0, 0x27, 0x8D, 0x0C, 0x82, 0xEA, 0xAE, 0xB4,
    0x9A, 0x63, 0x49, 0xE5, 0x42, 0xE4, 0x15, 0xB7,
    0xC8, 0x06, 0x70, 0x9D, 0x41, 0x75, 0x19, 0xC9,
    0xAA, 0xFC, 0x4D, 0xBF, 0x2A, 0x73, 0x84, 0xD5,
    0xC3, 0xAF, 0x2B, 0x86, 0xA7, 0xB1, 0xB2, 0x5B,
    0x46, 0xD3, 0x9F, 0xFD, 0xD4, 0x0F, 0x9C, 0x2F,
    0x9B, 0x43, 0xEF, 0xD9, 0x79, 0xB6, 0x53, 0x7F,
    0xC1, 0xF0, 0x23, 0xE7, 0x25, 0x5E, 0xB5, 0x1E,
    0xA2, 0xDF, 0xA6, 0xFE, 0xAC, 0x22, 0xF9, 0xE2,
    0x4A, 0xBC, 0x35, 0xCA, 0xEE, 0x78, 0x05, 0x6B,
    0x51, 0xE1, 0x59, 0xA3, 0xF2, 0x71, 0x56, 0x11,
    0x6A, 0x89, 0x94, 0x65, 0x8C, 0xBB, 0x77, 0x3C,
    0x7B, 0x28, 0xAB, 0xD2, 0x31, 0xDE, 0xC4, 0x5F,
    0xCC, 0xCF, 0x76, 0x2C, 0xB8, 0xD8, 0x2E, 0x36,
    0xDB, 0x69, 0xB3, 0x14, 0x95, 0xBE, 0x62, 0xA1,
    0x3B, 0x16, 0x66, 0xE9, 0x5C, 0x6C, 0x6D, 0xAD,
    0x37, 0x61, 0x4B, 0xB9, 0xE3, 0xBA, 0xF1, 0xA0,
    0x85, 0x83, 0xDA, 0x47, 0xC5, 0xB0, 0x33, 0xFA,
    0x96, 0x6F, 0x6E, 0xC2, 0xF6, 0x50, 0xFF, 0x5D,
    0xA9, 0x8E, 0x17, 0x1B, 0x97, 0x7D, 0xEC, 0x58,
    0xF7, 0x1F, 0xFB, 0x7C, 0x09, 0x0D, 0x7A, 0x67,
    0x45, 0x87, 0xDC, 0xE8, 0x4F, 0x1D, 0x4E, 0x04,
    0xEB, 0xF8, 0xF3, 0x3E, 0x3D, 0xBD, 0x8A, 0x88,
    0xDD, 0xCD, 0x0B, 0x13, 0x98, 0x02, 0x93, 0x80,
    0x90, 0xD0, 0x24, 0x34, 0xCB, 0xED, 0xF4, 0xCE,
    0x99, 0x10, 0x44, 0x40, 0x92, 0x3A, 0x01, 0x26,
    0x12, 0x1A, 0x48, 0x68, 0xF5, 0x81, 0x8B, 0xC7,
    0xD6, 0x20, 0x0A, 0x08, 0x00, 0x4C, 0xD7, 0x74
};

//Обратное преобразование S
static void
GOST_Kuz_reverse_S(const uint8_t* in_data, uint8_t* out_data)
{
    int i;
    for (i = 0; i < BLOCK_SIZE; i++)
        out_data[i] = reverse_Pi[in_data[i]];
}

//сложение по модулю 2
static void
GOST_Kuz_X(const uint8_t* a, const uint8_t* b, uint8_t* c)
{
    int i;
    for (i = 0; i < BLOCK_SIZE; i++)
        c[i] = a[i] ^ b[i];
}

//Функции для линейного преобразования L

/*
функция умножения чисел в поле Галуа над неприводимым полиномом 
x^8 + x^7 + x^6 + x + 1
*/
static uint8_t
GOST_Kuz_GF_mul(uint8_t a, uint8_t b)
{
    uint8_t c = 0;
    uint8_t hi_bit;
    int i;
    for (i = 0; i < 8; i++)
    {
        if (b & 1)
            c ^= a;
        hi_bit = a & 0x80;
        a <<= 1;
        if (hi_bit)
            a ^= 0xc3; //полином x^8+x^7+x^6+x+1
        b >>= 1;
    }
    return c;
}

//массив коэффициентов для преобразования R
static const unsigned char l_vec[16] = {
    1, 148, 32, 133, 16, 194, 192, 1,
    251, 1, 192, 194, 16, 133, 32, 148
};

//функция преобразования R (побайтовый сдвиг)
static void
GOST_Kuz_R(uint8_t* state)
{
    int i;
    uint8_t a_15 = 0;
    vect internal;
    for (i = 15; i > 0; i--)
    {
        internal[i - 1] = state[i];// Двигаем байты в сторону младшего разряда
        a_15 ^= GOST_Kuz_GF_mul(state[i], l_vec[i]);
    }
    //складываем первый байт, который не был учтён в цикле
    a_15 ^= GOST_Kuz_GF_mul(state[i], l_vec[i]);

    //Пишем в последний байт результат сложения
    internal[15] = a_15;
    memcpy(state, internal, BLOCK_SIZE);
}

//Обратное преобразование R
static void
GOST_Kuz_reverse_R(uint8_t* state)
{
    int i;
    uint8_t a_0;
    a_0 = state[15];
    vect internal;
    //в a_0 уже хранится байт
    for (i = 1; i < 16; i++)
    {
        internal[i] = state[i - 1];//Двигаем все на старые места
        a_0 ^= GOST_Kuz_GF_mul(internal[i], l_vec[i]);
    }
    internal[0] = a_0;
    memcpy(state, internal, BLOCK_SIZE);
}

/*
Линейное преобразование L, которое обрразуется путем 16 кратного 
повторения GOST_Kuz_R (сдвиг регистра 16 раз)
*/
static void
GOST_Kuz_L(const uint8_t* in_data, uint8_t* out_data)
{
    int i;
    vect internal;
    memcpy(internal, in_data, BLOCK_SIZE);
    for (i = 0; i < 16; i++)
        GOST_Kuz_R(internal);
    memcpy(out_data, internal, BLOCK_SIZE);
}

//Обратное линейное преобразование
static void
GOST_Kuz_reverse_L(const uint8_t* in_data, uint8_t* out_data)
{
    int i;
    vect internal;
    memcpy(internal, in_data, BLOCK_SIZE);
    for (i = 0; i < 16; i++)
        GOST_Kuz_reverse_R(internal);
    memcpy(out_data, internal, BLOCK_SIZE);
}

//Функции для работы с ключами

//итерационные константы C
vect iter_C[32]; 

//Функция вычисление итерационных констант
static void
GOST_Kuz_Get_C()
{
    int i;
    vect iter_num[32];
    for (i = 0; i < 32; i++)
    {
        memset(iter_num[i], 0, BLOCK_SIZE);
        iter_num[i][0] = i + 1;
    }
    for (i = 0; i < 32; i++)
        GOST_Kuz_L(iter_num[i], iter_C[i]);
}

//функция, которая представляет одну итерацию развертывания ключа
static void
GOST_Kuz_F(const uint8_t* in_key_1, const uint8_t* in_key_2,
    uint8_t* out_key_1, uint8_t* out_key_2,
    uint8_t* iter_const)
{
    vect internal;
    memcpy(out_key_2, in_key_1, BLOCK_SIZE);
    GOST_Kuz_X(in_key_1, iter_const, internal);
    GOST_Kuz_S(internal, internal);
    GOST_Kuz_L(internal, internal);
    GOST_Kuz_X(internal, in_key_2, out_key_1);
}

vect iter_key[10]; //итерационные ключи шифрования

//непосредственное развертывание ключей
void
GOST_Kuz_Expand_Key(const uint8_t* key_1, const uint8_t* key_2)
{
    int i;
    uint8_t iter_1[64];
    uint8_t iter_2[64];
    uint8_t iter_3[64];
    uint8_t iter_4[64];
    GOST_Kuz_Get_C();
    memcpy(iter_key[0], key_1, 64);
    memcpy(iter_key[1], key_2, 64);
    memcpy(iter_1, key_1, 64);
    memcpy(iter_2, key_2, 64);
    for (i = 0; i < 4; i++)
    {
        GOST_Kuz_F(iter_1, iter_2, iter_3, iter_4, iter_C[0 + 8 * i]);
        GOST_Kuz_F(iter_3, iter_4, iter_1, iter_2, iter_C[1 + 8 * i]);
        GOST_Kuz_F(iter_1, iter_2, iter_3, iter_4, iter_C[2 + 8 * i]);
        GOST_Kuz_F(iter_3, iter_4, iter_1, iter_2, iter_C[3 + 8 * i]);
        GOST_Kuz_F(iter_1, iter_2, iter_3, iter_4, iter_C[4 + 8 * i]);
        GOST_Kuz_F(iter_3, iter_4, iter_1, iter_2, iter_C[5 + 8 * i]);
        GOST_Kuz_F(iter_1, iter_2, iter_3, iter_4, iter_C[6 + 8 * i]);
        GOST_Kuz_F(iter_3, iter_4, iter_1, iter_2, iter_C[7 + 8 * i]);
        memcpy(iter_key[2 * i + 2], iter_1, 64);
        memcpy(iter_key[2 * i + 3], iter_2, 64);
    }
    /*
#ifdef DEBUG_MODE
    printf("Iteration cipher keys:\n");
    for (i = 0; i < 10; i++)
        GOST_Kuz_PrintDebug(iter_key[i]);
#endif
*/
}

//непосредственное шифрование (необходимо прежде запустить функцию GOST_Kuz_Expand_Key)
void
GOST_Kuz_Encript(const uint8_t* blk, uint8_t* out_blk)
{
    int i;
    memcpy(out_blk, blk, BLOCK_SIZE);
    /*
#ifdef DEBUG_MODE
    printf("Text:\n");
    GOST_Kuz_PrintDebug(out_blk);
#endif
*/
    for (i = 0; i < 9; i++)
    {
        GOST_Kuz_X(iter_key[i], out_blk, out_blk);

        GOST_Kuz_S(out_blk, out_blk);

        GOST_Kuz_L(out_blk, out_blk);
    }
    GOST_Kuz_X(out_blk, iter_key[9], out_blk);
    /*
#ifdef DEBUG_MODE
    printf("Encripting text:\n");
    GOST_Kuz_PrintDebug(out_blk);
#endif
*/
}

//расшифровка (необходимо прежде запустить функцию GOST_Kuz_Expand_Key)
void
GOST_Kuz_Decript(const uint8_t* blk, uint8_t* out_blk)
{
    int i;
    memcpy(out_blk, blk, BLOCK_SIZE);
    /*
#ifdef DEBUG_MODE
    printf("Gipher text:\n");
    GOST_Kuz_PrintDebug(out_blk);
#endif
    */
    GOST_Kuz_X(out_blk, iter_key[9], out_blk);
    for (i = 8; i >= 0; i--)
    {
        GOST_Kuz_reverse_L(out_blk, out_blk);

        GOST_Kuz_reverse_S(out_blk, out_blk);

        GOST_Kuz_X(iter_key[i], out_blk, out_blk);
    }
    /*
#ifdef DEBUG_MODE
    printf("Decripting text:\n");
    GOST_Kuz_PrintDebug(out_blk);
#endif
*/
}

//Работа с основной функцией шифрование в ZFS
void aes_generic_encrypt(const uint32_t rk[], int Nr,
    const uint32_t pt[4], uint32_t ct[4])
{
    //Преобразования ключа к типу данных uint8_t
    uint8_t* key_p = (uint8_t*)rk;

    //Преобразование входных данных
    uint8_t* blk = (uint8_t*)pt;

    //Преобразование выходных данных
    uint8_t* out_blk = (uint8_t*)ct;

    //Ввод ключей
    GOST_Kuz_Expand_Key(key_p, key_p);

    //Шифроввание
    GOST_Kuz_Encript(blk, out_blk);
}

//Работа с основной функцией дешифрование в ZFS
void aes_generic_decrypt(const uint32_t rk[], int Nr,
    const uint32_t ct[4], uint32_t pt[4])
{
    //Преобразования ключа к типу данных uint8_t
    uint8_t* key_p = (uint8_t*)rk;

    //Преобразование выходных данных
    uint8_t* out_blk = (uint8_t*)pt;

    //Преобразование входных данных
    uint8_t* blk = (uint8_t*)ct;

    //Ввод ключей
    GOST_Kuz_Expand_Key(key_p, key_p);

    //Дешифроввание
    GOST_Kuz_Decript(blk, out_blk);
}