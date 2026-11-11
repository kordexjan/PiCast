/* Execute the real vendor client with synthetic kernel replies: no sockets,
 * radio or hardware writes. Linux linker wrapping intercepts every I/O call. */
#include "picast.h"
#include <assert.h>
#include <linux/genetlink.h>
#include <linux/nl80211.h>
#include <net/if.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
static unsigned mode,writes,requests;static int candidate,short_monitor;
static unsigned char last[256];static size_t last_n;
int pc_print_awdl(const uint8_t *p,size_t n){(void)p;(void)n;assert(0);return 1;}
int __wrap_socket(int a,int b,int c){(void)a;(void)b;(void)c;return 123;}
int __wrap_bind(int f,const struct sockaddr *a,socklen_t n){(void)a;(void)n;assert(f==123);return 0;}
int __wrap_close(int f){assert(f==123);return 0;}
unsigned __wrap_if_nametoindex(const char *n){assert(!strcmp(n,"picastmon"));return 1;}
int __wrap_poll(struct pollfd *p,nfds_t n,int t){(void)t;assert(n==1&&p->fd==123);p->revents=POLLIN;return 1;}
ssize_t __wrap_sendto(int f,const void *b,size_t n,int flags,const struct sockaddr *a,socklen_t len){
 (void)flags;(void)a;(void)len;assert(f==123&&n<=sizeof(last));memcpy(last,b,n);last_n=n;requests++;return (ssize_t)n;
}
static size_t attr(unsigned char *b,size_t at,unsigned type,const void *v,size_t n){
 struct nlattr h={.nla_type=(unsigned short)type,.nla_len=(unsigned short)(4+n)};memcpy(b+at,&h,4);memcpy(b+at+4,v,n);return at+((4+n+3)&~(size_t)3);
}
ssize_t __wrap_recvfrom(int f,void *buffer,size_t cap,int flags,struct sockaddr *a,socklen_t *alen){
 (void)flags;assert(f==123&&cap>=2048);struct sockaddr_nl sender={.nl_family=AF_NETLINK};memcpy(a,&sender,sizeof(sender));*alen=sizeof(sender);
 unsigned char out[2048]={0};struct nlmsghdr h;memcpy(&h,last,sizeof(h));h.nlmsg_flags=0;
 struct genlmsghdr g={.cmd=NL80211_CMD_VENDOR,.version=1};size_t n=20;
 if(h.nlmsg_type==GENL_ID_CTRL){unsigned short family=42;g.cmd=CTRL_CMD_NEWFAMILY;n=attr(out,n,CTRL_ATTR_FAMILY_ID,&family,2);}
 else{
  const unsigned char *v;size_t vn;assert(!pc_netlink_attr(last+20,last_n-20,NL80211_ATTR_VENDOR_DATA,&v,&vn));
  unsigned hdr[5];assert(vn>=20);memcpy(hdr,v,20);unsigned char data[768]={0};size_t bytes=hdr[1];assert(bytes<=sizeof(data));
  if(hdr[3]){
   assert(hdr[0]==263&&hdr[1]==8&&hdr[2]==20&&hdr[3]==1&&vn==28);
   assert(!memcmp(v+20,"mpc\0\0\0\0\0",8));assert(mode==2&&candidate&&!short_monitor);writes++;
  }else if(hdr[0]==107){memcpy(data,&mode,4);if(short_monitor)bytes=3;}
  else{assert(hdr[0]==262);if(!strcmp((const char *)v+20,"ver"))strcpy((char *)data,candidate?"9.88.4.65 (nexmon.org: 68720406-picast-7)":"9.88.4.77 stock");else assert(!strcmp((const char *)v+20,"cap"));}
  unsigned char nested[900]={0};unsigned short size=(unsigned short)bytes;size_t used=attr(nested,0,1,&size,2);used=attr(nested,used,2,data,bytes);n=attr(out,n,NL80211_ATTR_VENDOR_DATA,nested,used);
 }
 h.nlmsg_len=(unsigned)n;memcpy(out,&h,16);memcpy(out+16,&g,4);memcpy(buffer,out,n);return (ssize_t)n;
}
int main(void){
 assert(pc_firmware_monitor_awake("wlan0")==2&&!requests);
 for(mode=0;mode<=3;mode++)for(candidate=0;candidate<=1;candidate++)for(short_monitor=0;short_monitor<=1;short_monitor++){
  writes=requests=0;int result=pc_firmware_monitor_awake("picastmon");int allowed=mode==2&&candidate&&!short_monitor;
  assert((result==0)==allowed);assert(writes==(unsigned)allowed);
 }
 puts("fixed MPC write: only qualified monitor2; wrong interface, stock version and malformed replies refused");
}
