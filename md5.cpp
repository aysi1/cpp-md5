#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>


/*

                Copyright (C) 2019  ayoub sirai

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

*/

class MD5 {
    private:
        uint32_t h0, h1, h2, h3, *w, pos, a, b, c, d, f, g, temp;
        char *__hex_digest;
        uint8_t *msg, *__digest;
        uint64_t sz;
        uint32_t r[64] =	{
				7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
				5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
				4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
				6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
				};
	    uint32_t k[64]  =   {
        			0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
        			0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        			0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        			0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        			0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
        			0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        			0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        			0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
       				0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        			0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        			0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
        			0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        			0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
        			0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        			0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        			0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
        	};
    public:
        MD5();
        void Update(const uint8_t*, uint64_t);
        void Final();
        uint8_t *digest();
        char *hex_digest();
    protected:
        uint32_t left_rotate(uint32_t x, uint32_t n) {
            return ((x << n) | (x >> (32 - n)));
        }
        void apply_md5_on_block() {
            w = (uint32_t *) (msg + 64 * pos);
            a=h0;
		    b=h1;
		    c=h2;
		    d=h3;
		    for (int i=0; i<64; i++) {
			    if (i<16) {
				    f=(b & c) | ((~b) & d);
				    g=i;
			    }
			    else if (i<32) {
			    	f=(d & b) | ((~d) & c);
			    	g=(5*i+1)%16;
			    }
			    else if (i<48) {
			    	f=b ^ c ^ d;
			    	g=(3*i+5)%16;
			    }
			    else {
			    	f=c ^ (b | (~d));
			    	g=(7*i)%16;
			    }
			    temp=d;
			    d=c;
			    c=b;
			    b=left_rotate(a+f+k[i]+w[g], r[i]) + b;
			    a=temp;
		    }
		    h0+=a;
		    h1+=b;
		    h2+=c;
		    h3+=d;
            pos++;
        }
};

MD5::MD5() : sz(0), pos(0), h0(0x67452301), h1(0xEFCDAB89), h2(0x98BADCFE), h3(0x10325476) {}


void MD5::Update(const uint8_t *buffer, uint64_t __sz) {
    uint8_t *m = new uint8_t[sz+__sz];
    memset(m, 0, sz+__sz);
    if (sz != 0) memcpy(m, msg, sz);
    memcpy(m+sz, buffer, __sz);
    int q1 = sz/64;
    sz+=__sz;
    msg = m;
    int q2 = sz/64;
    for (int i=q1; i<q2; i++)
        apply_md5_on_block();
}

void MD5::Final() {
    uint32_t sz0 = 64 * (sz/64), sz1 = sz - 64 * (sz/64), sz2;
    for (sz2=8*sz1+8; sz2%512!=448; sz2+=8);
    uint64_t __rsize = sz1*8;
    sz2/=8;
    uint8_t *fmsg = new uint8_t[sz2+8+1];
    memset(fmsg, 0, sz2+8+1);
    memcpy(fmsg, msg+sz0, sz1);
    fmsg[sz1]=128;
    memcpy(fmsg+sz2, &__rsize, sizeof(uint64_t));
    for (int j=0; j<(sz2+8)/64; j++) {
            w = (uint32_t *) (fmsg + 64 * j);
            a=h0;
		    b=h1;
		    c=h2;
		    d=h3;
		    for (int i=0; i<64; i++) {
			    if (i<16) {
				    f=(b & c) | ((~b) & d);
				    g=i;
			    }
			    else if (i<32) {
			    	f=(d & b) | ((~d) & c);
			    	g=(5*i+1)%16;
			    }
			    else if (i<48) {
			    	f=b ^ c ^ d;
			    	g=(3*i+5)%16;
			    }
			    else {
			    	f=c ^ (b | (~d));
			    	g=(7*i)%16;
			    }
			    temp=d;
			    d=c;
			    c=b;
			    b=left_rotate(a+f+k[i]+w[g], r[i]) + b;
			    a=temp;
		    }
		    h0+=a;
		    h1+=b;
		    h2+=c;
		    h3+=d;
    }
    __digest = new uint8_t[16];
    memset(__digest, 0, 16);
	memcpy(__digest, &h0, sizeof(uint32_t));
	memcpy(__digest+4, &h1, sizeof(uint32_t));
	memcpy(__digest+8, &h2, sizeof(uint32_t));
	memcpy(__digest+12, &h3, sizeof(uint32_t));
    __hex_digest = new char[33];
    __hex_digest[32]=0;
    for (int i=0; i<16; i++)
		sprintf(__hex_digest+2*i, "%02x", __digest[i]);
}

uint8_t *MD5::digest() {
    return __digest;
}

char *MD5::hex_digest() {
    return __hex_digest;
}


int main(int argc, char *argv[]) {
    MD5 *md5 = new MD5();
    md5->Update((uint8_t *) "MD5", 3);
    md5->Update((uint8_t *) " ALGO", 5);
    md5->Update((uint8_t *) "RITHM", 5);
    md5->Final();
    std::cout << md5->hex_digest() << std::endl;
    return 0;
}

