#include <ctype.h>
#include <math.h>
#include <stdio.h>
#include <string.h>

#include "bech32.h"

static int convert_bits(uint8_t* out, size_t* outlen, int outbits, const uint8_t* in, size_t inlen, int inbits, int pad) {
    uint32_t val = 0;
    int bits = 0;
    uint32_t maxv = (((uint32_t)1) << outbits) - 1;
    while (inlen--) {
        val = (val << inbits) | *(in++);
        bits += inbits;
        while (bits >= outbits) {
            bits -= outbits;
            out[(*outlen)++] = (val >> bits) & maxv;
        }
    }
    if (pad) {
        if (bits) {
            out[(*outlen)++] = (val << (outbits - bits)) & maxv;
        }
    } else if (((val << (outbits - bits)) & maxv) || bits >= inbits) {
        return 0;
    }
    return 1;
}

static void append_bits(uint8_t* data_out, size_t* pos_in_bit_in_out, int32_t data_in, int in_bits) {
    uint32_t mask = (((uint32_t)1) << in_bits) - 1;
    int in_pos = 0;
    while (in_pos < in_bits) {
        data_out[*pos_in_bit_in_out / 8] |= ((data_in & mask) >> in_pos << (*pos_in_bit_in_out % 8)); 
        int written = (in_bits - in_pos) > (8-(*pos_in_bit_in_out % 8)) ? (8-(*pos_in_bit_in_out % 8)) : (in_bits - in_pos);
        in_pos += written;
        *pos_in_bit_in_out+= written;
    }
}

int xpriv(uint8_t *privkey, uint8_t *chaincode, uint32_t birthday, uint32_t gap_limit_multiplier, uint8_t script_type) {
    char hrp[32] = "xp";
    uint8_t data_in[128] = {};
    size_t data_in_len = 128;
    size_t pos = 0;
    append_bits(data_in, &pos, 0, 1);
    append_bits(data_in, &pos, birthday, 15);
    append_bits(data_in, &pos, gap_limit_multiplier, 9);
    append_bits(data_in, &pos, script_type, 8);
    for(int i = 0; i<32;i++) {
        append_bits(data_in, &pos, privkey[i], 8);
    }
    for(int i = 0; i<32;i++) {
        append_bits(data_in, &pos, chaincode[i], 8);
    }
    uint8_t data5[128] = {};
    size_t data5_len = 0;
    convert_bits(data5, &data5_len, 5, data_in, (int)ceil(pos/8.0), 8, 1);

    char bech32_str[128];
    if (!bech32_encode(bech32_str, hrp, data5, data5_len)) {
        printf("Encode failed\n");
    }
    printf("Bech32 encoded string: %s\n", bech32_str);

    uint8_t dblcheck5[100] = {};
    size_t dblcheck5_len = 0;
    if (!bech32_decode(hrp, dblcheck5, &dblcheck5_len, bech32_str)) {
        printf("bech32_decode fails: '%s'\n", bech32_str);
    }
    uint8_t dblcheck8[100] = {};
    size_t dblcheck8_len = 0;
    convert_bits(dblcheck8, &dblcheck8_len, 8, dblcheck5, dblcheck5_len, 5, 1);
    if (memcmp(dblcheck8, data_in, (int)ceil(pos/8.0)) != 0) {
        printf("Failed\n");
        return 1;
    }
    int c_version = (dblcheck8[0] & 1);
    uint32_t c_birthday = (dblcheck8[0] & 0xFE) >> 1;
    c_birthday |= (dblcheck8[1] & 0xFF) << 7;
    uint32_t c_gap_limit = dblcheck8[2];
    c_gap_limit |= (dblcheck8[3] & 0x1) << 8;
    uint32_t c_script_type = (dblcheck8[3] & 0xFE) >> 1;
    c_script_type |= (dblcheck8[4] & 1) << 7;
    printf("Version: %d\n", c_version);
    printf("Birthday: %d\n", c_birthday);
    printf("Gap-limit-multiplier: %d\n", c_gap_limit);
    printf("Resulting Gap-limit: %d\n", (c_gap_limit+1)*100);
    printf("script_type: %d\n", c_script_type);
    printf("===================\n");
    return 0;
}

int wif(uint8_t *privkey, uint32_t birthday, uint8_t script_type) {
    char hrp[32] = "pk";
    uint8_t data_in[128] = {};
    size_t data_in_len = 128;
    size_t pos = 0;
    append_bits(data_in, &pos, 0, 1);
    append_bits(data_in, &pos, birthday, 15);
    append_bits(data_in, &pos, script_type, 8);
    for(int i = 0; i<32;i++) {
        append_bits(data_in, &pos, privkey[i], 8);
    }
    uint8_t data5[128] = {};
    size_t data5_len = 0;
    convert_bits(data5, &data5_len, 5, data_in, (int)ceil(pos/8.0), 8, 1);

    char bech32_str[128] = {0};
    if (!bech32_encode(bech32_str, hrp, data5, data5_len)) {
        printf("Encode failed\n");
    }
    printf("Bech32 encoded string: %s\n", bech32_str);

    uint8_t dblcheck5[100] = {};
    size_t dblcheck5_len = 0;
    if (!bech32_decode(hrp, dblcheck5, &dblcheck5_len, bech32_str)) {
        printf("bech32_decode fails: '%s'\n", bech32_str);
    }
    uint8_t dblcheck8[100] = {};
    size_t dblcheck8_len = 0;
    convert_bits(dblcheck8, &dblcheck8_len, 8, dblcheck5, dblcheck5_len, 5, 1);
    if (memcmp(dblcheck8, data_in, (int)ceil(pos/8.0)) != 0) {
        printf("Failed\n");
        return 1;
    }
    int c_version = (dblcheck8[0] & 1);
    uint32_t c_birthday = (dblcheck8[0] & 0xFE) >> 1;
    c_birthday |= (dblcheck8[1] & 0xFF) << 7;
    uint32_t c_script_type = dblcheck8[2];
    printf("Version: %d\n", c_version);
    printf("Birthday: %d\n", c_birthday);
    printf("script_type: %d\n", c_script_type);
    return 0;
}

int main(void) {
    uint8_t privkey[32] = {0x71, 0x54, 0x70, 0x43, 0x29, 0xd1, 0x17, 0x25, 0xd1, 0xbf, 0x5a, 0x6d,
  0x44, 0x9c, 0x80, 0xdf, 0xb9, 0x3f, 0xf2, 0x27, 0xa0, 0x7d, 0xac, 0x75,
  0xb9, 0x78, 0x88, 0xe8, 0x56, 0x84, 0x7e, 0xb5};
  uint8_t chaincode[32] = {0x50, 0x1a, 0x4f, 0x15, 0x2d, 0x1d, 0xb6, 0xb8, 0x48, 0xdb, 0x6e, 0xe2,
  0x05, 0xfa, 0x18, 0xee, 0x5c, 0x6d, 0x25, 0x02, 0x3d, 0x7c, 0xec, 0x47,
  0x59, 0x87, 0x8f, 0x1a, 0x46, 0x57, 0x82, 0x8c};
  
    //birthday: monday, 7. July 2014 (2011 days since january 3th 2009)
    //gap-limit-mp 10 = (10 + 1) * 100 == gaplimit of 1100
    //script type restriction to P2PKH compressed
    xpriv(privkey, chaincode, 2011, 10, 1); 

    xpriv(privkey, chaincode, 0, 0, 0); //3rd Jan 2009, glm of 0, no script type restrictions
    xpriv(privkey, chaincode, 32767, 511, 255); // Saturday, September 2098
    wif(privkey, 32767, 255);
}
