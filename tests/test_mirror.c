#include "picast_mirror.h"
#include <assert.h>
#include <string.h>

void test_mirror(void) {
    uint8_t header[128]={3,0,0,0,0,0,6,0,8,7,6,5,4,3,2,1};
    struct pc_mirror_header parsed={0};
    for (size_t n=0;n<128;n++) assert(pc_mirror_header_parse(header,n,&parsed)==PC_OTHER && !parsed.payload_size);
    assert(pc_mirror_header_parse(header,128,&parsed)==PC_OK);
    assert(parsed.payload_size==3 && parsed.type==0 && parsed.flags==6 && parsed.ntp==UINT64_C(0x0102030405060708));
    header[5]=0x10;assert(pc_mirror_header_parse(header,128,&parsed)==PC_OK && parsed.type==0 && parsed.type_flags==0x1000);
    header[5]=0x20;assert(pc_mirror_header_parse(header,128,&parsed)==PC_UNSUPPORTED);
    header[4]=1;header[5]=0x10;assert(pc_mirror_header_parse(header,128,&parsed)==PC_UNSUPPORTED);
    header[5]=0;header[4]=5;assert(pc_mirror_header_parse(header,128,&parsed)==PC_OK && parsed.payload_size==3);
    header[0]=0x14;header[1]=0x63;assert(pc_mirror_header_parse(header,128,&parsed)==PC_OK && parsed.payload_size==25364);
    header[0]=0;header[1]=0;header[2]=1;assert(pc_mirror_header_parse(header,128,&parsed)==PC_OK && parsed.payload_size==65536);
    header[0]=1;assert(pc_mirror_header_parse(header,128,&parsed)==PC_INVALID);
    header[0]=3;header[1]=header[2]=0;
    header[4]=2;assert(pc_mirror_header_parse(header,128,&parsed)==PC_INVALID);
    header[0]=0;assert(pc_mirror_header_parse(header,128,&parsed)==PC_OK);
    header[4]=3;assert(pc_mirror_header_parse(header,128,&parsed)==PC_UNSUPPORTED);
    header[4]=0;assert(pc_mirror_header_parse(header,128,&parsed)==PC_INVALID);
    header[2]=0x20;assert(pc_mirror_header_parse(header,128,&parsed)==PC_INVALID);

    uint8_t avcc[]={1,66,0,30,0xff,0xe1,0,3,0x67,0x42,0,1,0,2,0x68,0};
    const uint8_t expected[]={0,0,0,1,0x67,0x42,0,0,0,0,1,0x68,0};
    uint8_t output[64];size_t written=99;struct pc_h264_config c={2};
    for (size_t n=0;n<sizeof(avcc);n++) {
        memset(output,0xa7,sizeof(output));
        assert(pc_h264_config_decode(avcc,n,&c,output,sizeof(output),&written)!=PC_OK && !written && c.length_bytes==2);
        for (size_t i=0;i<sizeof(output);i++) assert(output[i]==0xa7);
    }
    assert(pc_h264_config_decode(avcc,sizeof(avcc),&c,output,sizeof(expected),&written)==PC_OK);
    assert(c.length_bytes==4 && written==sizeof(expected) && !memcmp(output,expected,written));
    memset(output,0xa7,sizeof(output));
    assert(pc_h264_config_decode(avcc,sizeof(avcc),&c,output,sizeof(expected)-1,&written)==PC_INVALID && !written);
    for (size_t i=0;i<sizeof(output);i++) assert(output[i]==0xa7);
    avcc[4]=0xfe;assert(pc_h264_config_decode(avcc,sizeof(avcc),&c,output,sizeof(output),&written)==PC_UNSUPPORTED);
    avcc[4]=0xff;avcc[8]=0xe7;
    assert(pc_h264_config_decode(avcc,sizeof(avcc),&c,output,sizeof(output),&written)==PC_INVALID);
    avcc[8]=0x67;
    uint8_t extended[20];memcpy(extended,avcc,sizeof(avcc));extended[1]=100;
    memcpy(extended+16,(uint8_t[]){0xfc,0xf8,0xf8,0},4);
    assert(pc_h264_config_decode(extended,sizeof(extended),&c,output,sizeof(output),&written)==PC_OK);
    /* Real iPhone config (r160): High 3.0 with a non-standard 4-byte trailer
     * that must not reach the decoder. Only that exact trailer is tolerated. */
    uint8_t iphone[]={0x01,0x64,0x00,0x1e,0xff,0xe1,0x00,0x11,0x27,0x64,0x00,0x1e,0xac,0x13,0x14,0x50,0x54,0x16,0xfb,0xe6,
        0xe0,0x21,0xa0,0x20,0x40,0x01,0x00,0x04,0x28,0xee,0x3c,0xb0,0x02,0x00,0x00,0x00};
    assert(pc_h264_config_decode(iphone,sizeof(iphone),&c,output,sizeof(output),&written)==PC_OK);
    assert(c.length_bytes==4 && !memcmp(output,"\0\0\0\1\x27\x64\x00\x1e",8));
    /* Rewritten SPS is longer and ends before the unchanged PPS. */
    assert(written>29 && !memcmp(output+written-8,"\0\0\0\1\x28\xee\x3c\xb0",8));
    uint8_t iphone_sps[64];size_t iphone_sps_n=written-12;memcpy(iphone_sps,output+4,iphone_sps_n);
    /* An SPS that already declares it stays as is: feed the result back. */
    uint8_t again[64]={0x01,0x64,0x00,0x1e,0xff,0xe1,0,(uint8_t)iphone_sps_n};
    memcpy(again+8,iphone_sps,iphone_sps_n);
    memcpy(again+8+iphone_sps_n,"\x01\x00\x04\x28\xee\x3c\xb0",7);
    assert(pc_h264_config_decode(again,8+iphone_sps_n+7,&c,output,sizeof(output),&written)==PC_OK);
    assert(written==iphone_sps_n+12 && !memcmp(output+4,iphone_sps,iphone_sps_n));
    iphone[35]=1;assert(pc_h264_config_decode(iphone,sizeof(iphone),&c,output,sizeof(output),&written)==PC_INVALID);
    iphone[35]=0;iphone[1]=66;assert(pc_h264_config_decode(iphone,sizeof(iphone),&c,output,sizeof(output),&written)==PC_UNSUPPORTED);

    uint8_t au[]={0,0,0,2,0x65,0x80,0,0,0,3,0x41,0xaa,0xbb};
    const uint8_t annex[]={0,0,0,1,0x65,0x80,0,0,0,1,0x41,0xaa,0xbb};
    assert(pc_h264_access_unit(&c,au,sizeof(au),output,sizeof(output),&written)==PC_OK);
    assert(written==sizeof(annex) && !memcmp(output,annex,written));
    for (size_t n=1;n<sizeof(au);n++) {
        if (n==6) continue; /* one complete NAL is a valid access unit */
        memset(output,0xa7,sizeof(output));
        assert(pc_h264_access_unit(&c,au,n,output,sizeof(output),&written)!=PC_OK && !written);
        for (size_t i=0;i<sizeof(output);i++) assert(output[i]==0xa7);
    }
    au[9]=0;memset(output,0xa7,sizeof(output)); /* invalid second NAL: no partial first output */
    assert(pc_h264_access_unit(&c,au,sizeof(au),output,sizeof(output),&written)==PC_INVALID && !written);
    for (size_t i=0;i<sizeof(output);i++) assert(output[i]==0xa7);
    c.length_bytes=0;assert(pc_h264_access_unit(&c,au,sizeof(au),output,sizeof(output),&written)==PC_UNSUPPORTED);
    c.length_bytes=1;
    assert(pc_h264_access_unit(&c,(uint8_t[]){2,0x65,0x80},3,output,sizeof(output),&written)==PC_OK && written==6);
    c.length_bytes=2;
    assert(pc_h264_access_unit(&c,(uint8_t[]){0,2,0x65,0x80},4,output,sizeof(output),&written)==PC_OK && written==6);

    uint32_t rng=91;uint8_t fuzz[256];
    for (unsigned sample=0;sample<10000;sample++) {
        for (size_t i=0;i<sizeof(fuzz);i++) { rng^=rng<<13;rng^=rng>>17;rng^=rng<<5;fuzz[i]=(uint8_t)rng; }
        size_t size=sample%sizeof(fuzz);
        (void)pc_mirror_header_parse(fuzz,size,&parsed);
        (void)pc_h264_config_decode(fuzz,size,&c,output,sizeof(output),&written);
        (void)pc_h264_access_unit(&c,fuzz,size,output,sizeof(output),&written);
    }
}
