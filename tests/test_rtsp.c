#include "picast_rtsp.h"
#include <assert.h>
#include <string.h>

static int parse_text(const char *text) {
    struct pc_rtsp_request r;
    return pc_rtsp_parse((const uint8_t *)text,strlen(text),&r);
}
void test_rtsp(void) {
    /* Synthetic AirPlay-shaped framing; not a captured Apple session. */
    static const uint8_t message[]="GET /info RTSP/1.0\r\nContent-Length: 5\r\nContent-Type: application/x-apple-binary-plist\r\nCSeq: 0\r\n\r\nb\0abc";
    struct pc_rtsp_request r;
    size_t n=sizeof(message)-1;
    for(size_t i=0;i<n;i++) {
        r.consumed=999;
        assert(pc_rtsp_parse(message,i,&r)==PC_OTHER && r.consumed==999);
    }
    assert(pc_rtsp_parse(message,n,&r)==PC_OK && r.consumed==n && !r.http && r.has_cseq && r.cseq==0);
    assert(r.method.size==3 && !memcmp(r.method.data,"GET",3));
    assert(r.target.size==5 && !memcmp(r.target.data,"/info",5));
    assert(r.body.size==5 && !memcmp(r.body.data,"b\0abc",5));
    struct pc_span value;
    assert(pc_rtsp_header(&r,"content-TYPE",&value)==PC_OK && value.size==32);
    assert(pc_rtsp_header(&r,"missing",&value)==PC_OTHER && !value.data && !value.size);
    uint8_t out[512]; size_t written=99;
    assert(pc_rtsp_response(&r,200,"application/octet-stream",r.body.data,r.body.size,out,sizeof(out),&written)==PC_OK);
    const char *header="RTSP/1.0 200 OK\r\nCSeq: 0\r\nServer: PiCast/0.1\r\nContent-Type: application/octet-stream\r\nContent-Length: 5\r\n\r\n";
    assert(written==strlen(header)+5 && !memcmp(out,header,strlen(header)) && !memcmp(out+strlen(header),"b\0abc",5));
    assert(pc_rtsp_response(&r,200,NULL,NULL,0,out,8,&written)==PC_INVALID && !written);
    assert(pc_rtsp_response(&r,200,"x\r\nInjected:1",NULL,0,out,sizeof(out),&written)==PC_UNSUPPORTED && !written);
    assert(pc_rtsp_response(&r,999,NULL,NULL,0,out,sizeof(out),&written)==PC_UNSUPPORTED && !written);
    const char *pipeline="OPTIONS * RTSP/1.0\r\nCSeq:1\r\n\r\nOPTIONS / RTSP/1.0\r\ncSeQ:\t2 \t\r\nContent-Length: 0\r\n\r\n";
    assert(pc_rtsp_parse((const uint8_t *)pipeline,strlen(pipeline),&r)==PC_OK && r.cseq==1);
    size_t first=r.consumed;
    assert(pc_rtsp_parse((const uint8_t *)pipeline+first,strlen(pipeline)-first,&r)==PC_OK && r.cseq==2);
    assert(r.consumed+first==strlen(pipeline));
    assert(parse_text("GET /info HTTP/1.1\r\nHost: picast.local\r\n\r\n")==PC_OK);
    assert(parse_text("OPTIONS * RTSP/2.0\r\nCSeq: 1\r\n\r\n")==PC_UNSUPPORTED);
    const char *bad[]={
        "GET / RTSP/1.0\r\n\r\n",
        "GET / RTSP/1.0\r\nCSeq:-1\r\n\r\n",
        "GET / RTSP/1.0\r\nCSeq:4294967296\r\n\r\n",
        "GET / RTSP/1.0\r\nCSeq:1\r\nCSeq:1\r\n\r\n",
        "GET / RTSP/1.0\r\nCSeq:1\r\nContent-Length:0\r\nContent-Length:0\r\n\r\n",
        "GET / RTSP/1.0\r\nCSeq:1\r\nContent-Length:65537\r\n\r\n",
        "GET / RTSP/1.0\r\nCSeq:1\r\nContent-Length:4,4\r\n\r\n",
        "GET / RTSP/1.0\r\nCSeq:1\r\nContent-Length :0\r\n\r\n",
        "GET / RTSP/1.0\r\nCSeq:1\r\n Folded: value\r\n\r\n",
        "GET / RTSP/1.0\nCSeq:1\n\n",
        "GET / RTSP/1.0\rX\r\n"
    };
    for(size_t i=0;i<sizeof(bad)/sizeof(bad[0]);i++) assert(parse_text(bad[i])==PC_INVALID);
    assert(parse_text("GET / RTSP/1.0\r\nCSeq:1\r\nTransfer-Encoding: chunked\r\n\r\n")==PC_UNSUPPORTED);
    assert(parse_text("GET / RTSP/1.0\r\nCSeq:1\r\nContent-Length:65536\r\n\r\n")==PC_OTHER);
    uint8_t oversized[PC_RTSP_HEADER_LIMIT]; memset(oversized,'a',sizeof(oversized));
    assert(pc_rtsp_parse(oversized,sizeof(oversized),&r)==PC_INVALID);
    uint8_t binary_header[]="GET / HTTP/1.1\r\nX:a\0b\r\n\r\n";
    assert(pc_rtsp_parse(binary_header,sizeof(binary_header)-1,&r)==PC_INVALID);
    assert(pc_rtsp_parse(NULL,0,&r)==PC_OTHER);
    assert(pc_rtsp_parse(NULL,1,&r)==PC_INVALID);
}
