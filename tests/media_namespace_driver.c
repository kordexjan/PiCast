#include "picast_media.h"
#include <assert.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#ifndef SO_NETNS_COOKIE
#define SO_NETNS_COOKIE 71
#endif
int main(void){
    int tun=-1,listener=-1,sockets[5];uint8_t own[6]={2,0x50,0x43,0,0,3};
    int host=socket(AF_INET6,SOCK_DGRAM,0);assert(host>=0);
    uint64_t host_cookie=0,cookie=0; socklen_t len=sizeof(cookie);
    assert(!getsockopt(host,SOL_SOCKET,SO_NETNS_COOKIE,&host_cookie,&len));
    assert(!pc_media_tun_open(own,&tun,&listener,sockets));
    int fds[6]={listener,sockets[0],sockets[1],sockets[2],sockets[3],sockets[4]};
    for(unsigned i=0;i<6;i++){
        struct sockaddr_in6 a={0};len=sizeof(a);assert(!getsockname(fds[i],(struct sockaddr *)&a,&len));assert(ntohs(a.sin6_port)==37000+i);
        uint64_t value=0;len=sizeof(value);assert(!getsockopt(fds[i],SOL_SOCKET,SO_NETNS_COOKIE,&value,&len));
        if(!i)cookie=value;
        assert(value==cookie && cookie!=host_cookie);close(fds[i]);
    }
    close(host);close(tun);puts("media namespace: six ports share one private namespace; host namespace untouched");
}
