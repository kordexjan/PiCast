#include "picast_fairplay.h"
#include "picast.h"
#include <openssl/evp.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
int main(void){
    const uint8_t first[16]={'F','P','L','Y',3,1,1,0,0,0,0,4,2,0,3,0xbb};
    struct pc_fairplay s={0};uint8_t out[200],next[164]={0};size_t written;
    memcpy(next,"FPLY\x03\x01\x03",7);next[11]=152;
    for(unsigned i=12;i<164;i++)next[i]=(uint8_t)i;
    assert(pc_fairplay_wire(&s,next,164,out,sizeof(out),&written)==PC_UNSUPPORTED && !s.phase && !written);
    memset(out,0xa7,sizeof(out));
    assert(pc_fairplay_wire(&s,first,16,out,141,&written)==PC_INVALID && !s.phase && !written);
    for(size_t i=0;i<sizeof(out);i++)assert(out[i]==0xa7);
    assert(pc_fairplay_wire(&s,first,16,out,sizeof(out),&written)==PC_OK && written==142 && s.phase==1);
    /* Independently calculated from the documented protocol data, not from
     * this source array. Header/type and the full opaque payload are bound. */
    uint8_t digest[32];unsigned size=0;
    const uint8_t expected[32]={0x8c,0x53,0xe0,0x3e,0x2a,0x08,0xe2,0x35,0x58,0xe4,0x82,0x87,0x85,0x1d,0x1c,0xf3,0x92,0x97,0x03,0x9a,0x7a,0x60,0xbf,0x90,0x6a,0x58,0x2e,0x22,0xc9,0x2f,0x82,0x6b};
    assert(EVP_Digest(out,written,digest,&size,EVP_sha256(),NULL)==1 && size==32 && !memcmp(digest,expected,32));
    assert(pc_fairplay_wire(&s,first,16,out,sizeof(out),&written)==PC_UNSUPPORTED && s.phase==1);
    assert(pc_fairplay_wire(&s,next,164,out,31,&written)==PC_INVALID && s.phase==1 && !written);
    assert(pc_fairplay_wire(&s,next,164,out,sizeof(out),&written)==PC_OK && written==32 && s.phase==2);
    const uint8_t header[12]={'F','P','L','Y',3,1,4,0,0,0,0,20};
    assert(!memcmp(out,header,12) && !memcmp(out+12,next+144,20) && !memcmp(s.key_message,next,164));
    assert(pc_fairplay_wire(&s,next,164,out,sizeof(out),&written)==PC_UNSUPPORTED);
    pc_fairplay_clear(&s);assert(!s.phase);
    for(size_t i=0;i<sizeof(s.key_message);i++)assert(!s.key_message[i]);
    for(unsigned n=0;n<200;n++){
        uint8_t input[200];memset(input,0x5a,sizeof(input));
        assert(pc_fairplay_wire(&s,input,n,out,sizeof(out),&written)!=PC_OK && !written && !s.phase);
    }
    for(unsigned i=0;i<15;i++){
        uint8_t changed[16];memcpy(changed,first,16);changed[i]^=0xff;
        assert(pc_fairplay_wire(&s,changed,16,out,sizeof(out),&written)!=PC_OK && !s.phase);
    }
    const char *hashes[]={
        "8e1a11ea61e4c397f30480910786893aaebb5bff59bf2074db9d7e84fda49dbc",
        "e3730ce34481b93312c97ecbebe5b2128ee16a8e4d0140e89904ac9ff7509df3",
        "c6ab6f9488d29f4c7ec395981cdd12f14a5fa5c51ce61ae6ce43c570f7eae989",
        "8c53e03e2a08e23558e48287851d1cf39297039a7a60bf906a582e22c92f826b"};
    for(unsigned mode=0;mode<4;mode++){
        uint8_t initial[16];memcpy(initial,first,16);initial[14]=(uint8_t)mode;
        pc_fairplay_clear(&s);
        assert(pc_fairplay_wire(&s,initial,16,out,sizeof(out),&written)==PC_OK && written==142 && out[13]==mode);
        assert(EVP_Digest(out,written,digest,&size,EVP_sha256(),NULL)==1 && size==32);
        char encoded[65];for(unsigned i=0;i<32;i++)snprintf(encoded+i*2,3,"%02x",digest[i]);
        assert(!strcmp(encoded,hashes[mode]));
        assert(pc_fairplay_wire(&s,next,164,out,sizeof(out),&written)==PC_OK && written==32);
    }
    pc_fairplay_clear(&s);
    puts("FairPlay wire: four documented response hashes, sequencing, key-message binding, bounds and malformed inputs passed; media-key decoder absent");
    return 0;
}
