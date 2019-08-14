/*
 * =====================================================================================
 *
 *       Filename:  temp.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2019年08月15日 01时29分59秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */

#include <stdio.h>

void printiphdr(char *p, __uint32_t len) {
	__uint32_t i;
	if (len > 100) {
		len = 100;
	}
	for (i = 0; i < len; i++) {
		if (i == 12 || i == 20) {
			printf("  ");
		}
		printf("%02hhx ", *p);
		p++;
	}
	printf("\n");
}

void encode(__uint8_t a, __uint8_t b, __uint16_t *id) {
	__uint8_t seq = *id % 64; //max 2^6=64
	__uint8_t *p = (__uint8_t *) id;
	*id = 0;
	*p |= a << 3;
	printiphdr((__uint8_t *)id, 2);
	// clear the first 3 bits of b and store the next 3 bits in high byte of id
	*p |= (b & 0x3c) >> 2;
	p++;
	// clear the first 6 bits of b and store the last 2 bits in high bit of low byte of id
	*p |= (b & 0x03) << 6;
	printiphdr((__uint8_t *)id, 2);
	*p |= seq;
	printiphdr((__uint8_t *)id, 2);
	// b=3 0000 0011  000 11
	// 08 c7 0000 1000 1100 0111
	printf("seq=%d id=%d\n", seq, *id);
}

void decode(__uint8_t *a, __uint8_t *b, __uint16_t *id) {
	__uint8_t *p = (__uint8_t *) id;
	*a = 0; *b = 0;
	*a |= *p >> 3;
	*b |= (*p & 0x07) << 2;
	p++;
	*b |= *p >> 6;
	*id = *p & 0x3f;
	printf("id=%d, a=%d b=%d\n", *id, *a, *b);
}

//255 63=2^6-1

void main() {
	__uint16_t id = 1223;
	encode(3, 3, &id);
	__uint8_t a, b;
	decode(&a, &b, &id);

	__uint8_t c = 13;
}


