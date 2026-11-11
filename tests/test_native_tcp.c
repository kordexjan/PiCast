#include "picast_tcp.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#ifdef __linux__
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
/* Socket-stream unit test only: never create a TUN or host listener here. */
int pc_media_tun_open(const uint8_t own[6],int *tun,int *listener,int sockets[5]) { (void)own;(void)tun;(void)listener;(void)sockets;return -1; }
static int attach(struct pc_tcp_diag *d) {
    int fds[2]; assert(socketpair(AF_UNIX,SOCK_STREAM|SOCK_NONBLOCK,0,fds)==0);
    d->client=fds[0]; return fds[1];
}
static void exchange(struct pc_tcp_diag *d,int peer,const char *request,unsigned expected) {
    /* Every input byte arrives separately; read exactly one response. */
    for (size_t i=0;i<strlen(request);i++) {
        assert(write(peer,request+i,1)==1); assert(pc_tcp_diag_step(d)==0);
    }
    uint8_t response[4097]={0};size_t used=0,total=0;
    for (unsigned i=0;i<100;i++) {
        assert(pc_tcp_diag_step(d)==0);
        ssize_t n=read(peer,response+used,4096-used);
        if(n<0) { assert(errno==EAGAIN || errno==EWOULDBLOCK);continue; }
        assert(n>0);used+=(size_t)n;response[used]=0;
        char *end=strstr((char *)response,"\r\n\r\n");
        char *length=strstr((char *)response,"Content-Length: ");
        if(end && length) total=(size_t)(end+4-(char *)response)+strtoul(length+16,NULL,10);
        if(total && used==total) break;
    }
    unsigned actual=0;assert(total && used==total);
    assert(sscanf((char *)response,"RTSP/1.0 %u",&actual)==1 && actual==expected);
}
int main(void) {
    struct pc_tcp_diag d={0}; uint8_t seed[32]={41},pub[32];
    d.tun=d.listener=d.client=-1;d.native_control=d.rtsp=1;
    memcpy(d.own,(uint8_t[]){2,1,2,3,4,5},6);
    assert(pc_control_init(&d.control,seed,1)==PC_OK);d.control_initialized=1;
    memcpy(d.control.device_id,d.own,6);memcpy(pub,d.control.identity_public,32);
    int peer=attach(&d);
    exchange(&d,peer,"GET /info RTSP/1.0\r\nCSeq: 0\r\n\r\n",200);
    exchange(&d,peer,"OPTIONS * RTSP/1.0\r\nCSeq: 19\r\n\r\n",200);
    assert(d.messages==2 && d.control.phase==PC_CONTROL_NEW);
    close(peer);assert(pc_tcp_diag_step(&d)==0 && d.client==-1);
    assert(!memcmp(pub,d.control.identity_public,32) && d.control.phase==PC_CONTROL_NEW);
    peer=attach(&d);
    exchange(&d,peer,"GET /info RTSP/1.0\r\nCSeq: 0\r\n\r\n",200);
    for (unsigned i=3;i<128;i++) exchange(&d,peer,"OPTIONS * RTSP/1.0\r\nCSeq: 25\r\n\r\n",200);
    assert(d.messages==128); /* the per-connection limit */
    const char *extra="OPTIONS * RTSP/1.0\r\nCSeq: 26\r\n\r\n";
    assert(write(peer,extra,strlen(extra))==(ssize_t)strlen(extra));
    assert(pc_tcp_diag_step(&d)==0 && d.messages==128);
    uint8_t byte;assert(read(peer,&byte,1)<0 && (errno==EAGAIN || errno==EWOULDBLOCK));
    /* Receiver-side end: the sender sees the close while the tunnel stays open. */
    d.tun=-1;pc_tcp_diag_hangup(&d);
    assert(d.client==-1 && d.listener==-1);
    assert(read(peer,&byte,1)==0 || errno==ECONNRESET);
    pc_tcp_diag_hangup(&d);
    close(peer);pc_tcp_diag_close(&d);
    memset(&d,0,sizeof(d));d.tun=d.listener=-1;d.rtsp=1;
    peer=attach(&d);
    const char *request="GET /info RTSP/1.0\r\nCSeq: 0\r\n\r\n";
    assert(write(peer,request,strlen(request))==(ssize_t)strlen(request));
    assert(pc_tcp_diag_step(&d)==-1); /* diagnostic policy still requires nonce */
    close(peer);pc_tcp_diag_close(&d);
    puts("native-control socket tests passed: fragmented CSeq0/no-token, stable reconnect identity, diagnostic nonce policy");
    return 0;
}
#else
int main(void) { puts("native-control socket tests require Linux; not executed");return 77; }
#endif
