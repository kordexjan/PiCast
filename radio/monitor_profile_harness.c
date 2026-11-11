/* Host-only ownership/bounds test for the actual candidate monitor function. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct sk_buff { unsigned char *data; short len; };
struct device;
struct functions { int (*xmit)(struct device *,struct device *,struct sk_buff *); };
struct device { struct device *chained; struct functions *funcs; };
struct wlif { struct device *dev; };
struct wlcif { struct wlcif *next; struct wlif *wlif; };
struct wlc_info { void *osh; struct wlcif *wlcif_list; };
struct wl_info { struct wlc_info *wlc; void *wlc_hw; struct device *dev; };
struct wl_rxsts { unsigned int chanspec; int signal; };
struct tsf { unsigned int tsf_l,tsf_h; };
struct ieee80211_radiotap_header { unsigned char it_version,it_pad; unsigned short it_len; unsigned int it_present; } __attribute__((packed));
struct nexmon_radiotap_header { struct ieee80211_radiotap_header header; struct tsf tsf; char flags; unsigned char data_rate; unsigned short chan_freq,chan_flags; char dbm_antsignal,dbm_antnoise; } __attribute__((packed));
#define IEEE80211_RADIOTAP_TSFT 0
#define IEEE80211_RADIOTAP_FLAGS 1
#define IEEE80211_RADIOTAP_CHANNEL 3
#define IEEE80211_RADIOTAP_DBM_ANTSIGNAL 5
#define IEEE80211_RADIOTAP_F_FCS 16
#define CHSPEC_CHANNEL(x) ((x)&255)
static struct sk_buff *fake_allocate(void *,unsigned int);
#define PC_MONITOR_PRIMARY_ALLOC(osh,n) fake_allocate((osh),(n))
#include "picast_monitor_profile.h"
static unsigned char input[PC_MONITOR_MAX_FRAME+64],storage[PC_MONITOR_MAX_FRAME+128];
static struct sk_buff original,created;
static int mode,allocations,pool_calls,sent,freed;
static unsigned int requested;
static struct device *expected_source;
static struct sk_buff *fake_allocate(void *osh,unsigned int n) {
    assert(osh==(void *)0x11); allocations++;requested=n;
    assert(n<sizeof(storage)-32);
    if(mode==1)return NULL;
    if(mode==4)return &original;
    created.data=mode==2 ? NULL : storage+16;
    created.len=(short)(mode==3 ? n-1 : n);
    return &created;
}
struct sk_buff *pkt_buf_get_skb(void *osh,unsigned int n) {pool_calls++;return fake_allocate(osh,n);}
void pkt_buf_free_skb(void *osh,struct sk_buff *p,int send) {assert(osh==(void *)0x11 && p==&created && send==0);freed++;}
void wlc_bmac_read_tsf(void *hw,unsigned int *lo,unsigned int *hi) {assert(hw==(void *)0x22);*lo=123;*hi=456;}
unsigned int wlc_phy_channel2freq(unsigned int ch) {return 2407+ch*5;}
static int transmit(struct device *source,struct device *target,struct sk_buff *p) {
    assert(source==expected_source && target==source->chained && p==&created);sent++;return 0;
}
/* ACTUAL_MONITOR_FUNCTION */
static struct functions funcs={transmit};
static struct device target={NULL,&funcs},source={&target,NULL},alternate={&target,NULL};
static struct wlif wlif={&alternate};
static struct wlcif next={NULL,NULL},interfaces={NULL,&wlif};
static struct wlc_info wlc={(void *)0x11,&interfaces};
static struct wl_info wl={&wlc,(void *)0x22,&source};
static struct wl_rxsts status={6,-42};
static void reset(void) {
    memset(input,0x55,sizeof(input));memset(storage,0xa5,sizeof(storage));
    unsigned char *frame=input+6;memset(frame,0,64);frame[0]=0x88;
    memcpy(frame+16,(unsigned char[]){0,0x25,0,0xff,0x94,0x73},6);
    original.data=input;original.len=70;mode=allocations=pool_calls=sent=freed=0;requested=0;
    expected_source=&source;interfaces.next=NULL;interfaces.wlif=&wlif;wl.dev=&source;wl.wlc=&wlc;wl.wlc_hw=(void *)0x22;wlc.osh=(void *)0x11;wlc.wlcif_list=&interfaces;
    source.chained=&target;target.funcs=&funcs;
}
static void reject(void) {wl_monitor_radiotap(&wl,&status,&original);assert(!allocations && !sent && !freed);}
static void verify_copy(void) {
    unsigned char before[sizeof(input)];memcpy(before,input,sizeof(input));short length=original.len;
    wl_monitor_radiotap(&wl,&status,&original);
    assert(allocations==1 && pool_calls==0 && sent==1 && !freed && original.len==length);
    assert(requested==(unsigned int)length-6+24 && created.len==(short)requested);
    assert(!memcmp(before,input,sizeof(input)));
    assert(!memcmp(created.data+24,input+6,(size_t)length-6));
    struct nexmon_radiotap_header h;memcpy(&h,created.data,24);
    assert(h.header.it_version==0 && h.header.it_pad==0 && h.header.it_len==24 && h.header.it_present==0x2b);
    assert(h.tsf.tsf_l==123 && h.tsf.tsf_h==456 && h.flags==16 && h.chan_freq==2437 && (unsigned char)h.dbm_antsignal==0xd6);
    assert(h.data_rate==0 && h.dbm_antnoise==0);
    for(unsigned int i=0;i<16;i++)assert(storage[i]==0xa5);
    for(unsigned int i=16+requested;i<sizeof(storage);i++)assert(storage[i]==0xa5);
}
int main(int argc,char **argv) {
    _Static_assert(sizeof(struct nexmon_radiotap_header)==24,"radiotap layout");
    reset();
    if(argc==2 && !strcmp(argv[1],"allocation-failure")) {mode=1;wl_monitor_radiotap(&wl,&status,&original);assert(allocations==1 && !sent);return 0;}
    for(int n=-32768;n<30;n++){reset();original.len=(short)n;reject();}
    for(int n=(int)PC_MONITOR_MAX_FRAME+7;n<=32767;n++){reset();original.len=(short)n;reject();}
    reset();verify_copy();
    reset();input[6]=0x08;verify_copy();
    reset();input[30]=0x80;verify_copy(); /* A-MSDU admission. */
    reset();input[6]=0xd0;memcpy(input+30,(unsigned char[]){0x7f,0,0x17,0xf2,8,0x10},6);verify_copy();
    reset();original.len=(short)(PC_MONITOR_MAX_FRAME+6);verify_copy();
    for(int m=1;m<=4;m+=3){reset();mode=m;wl_monitor_radiotap(&wl,&status,&original);assert(allocations==1 && !sent && !freed);}
    reset();input[22]^=1;reject(); /* Wrong BSSID. */
    reset();input[6]=0x80;reject(); /* Infrastructure beacon. */
    for(unsigned int bit=1;bit<=0x80;bit<<=1)if(bit&0xc7){reset();input[7]=(unsigned char)bit;reject();}
    reset();input[28]=1;reject(); /* Fragmented frame. */
    reset();input[6]=0xd0;reject(); /* Unrelated action. */
    reset();original.data=NULL;reject();
    reset();wl.wlc=NULL;reject();
    reset();wlc.osh=NULL;reject();
    reset();wl.wlc_hw=NULL;reject();
    reset();wlc.wlcif_list=NULL;reject();
    reset();source.chained=NULL;reject();
    reset();target.funcs=NULL;reject();
    reset();interfaces.next=&next;interfaces.wlif=NULL;reject();
    reset();wl_monitor_radiotap(NULL,&status,&original);assert(!allocations);
    reset();wl_monitor_radiotap(&wl,NULL,&original);assert(!allocations);
    reset();wl_monitor_radiotap(&wl,&status,NULL);assert(!allocations);
    reset();interfaces.next=&next;expected_source=&alternate;verify_copy();
    puts("monitor profile ownership, allocation failures, canaries and signed-length boundaries passed");
    return 0;
}
