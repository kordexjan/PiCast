/* Synthetic, isolated test driver. Never linked into the receiver. */
#define OPENSSL_SUPPRESS_DEPRECATED
#include "picast_srp.h"
#include <openssl/srp.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
static void hex(const uint8_t *p,size_t n) { for(size_t i=0;i<n;i++) printf("%02x",p[i]); }
static int readhex(uint8_t *out,size_t n) {
    for(size_t i=0;i<n;i++) { unsigned v; if(scanf("%2x",&v)!=1)return 0; out[i]=(uint8_t)v; }
    return 1;
}
int main(void) {
    struct pc_srp s={0}; uint8_t salt[16], b[256], a[256], proof[20], m2[20], key[16], iv[16];
    assert(pc_srp_keys(&s,key,iv)==-1);
    assert(pc_srp_start(&s,"02:01:02:03:04:05","1234",salt,b)==0);
    assert(pc_srp_start(&s,"02:01:02:03:04:05","1234",salt,b)==-1);
    const SRP_gN *group=SRP_get_default_gN("2048"); char *n=BN_bn2hex(group->N);
    printf("%s ",n); OPENSSL_free(n); hex(salt,16); putchar(' '); hex(b,256); putchar('\n'); fflush(stdout);
    assert(readhex(a,256) && readhex(proof,20));
    memset(m2,0xa7,sizeof(m2));
    int result=pc_srp_prove(&s,a,proof,m2);
    if(result) {
        for(size_t i=0;i<sizeof(m2);i++)assert(m2[i]==0xa7);
        assert(!s.phase && !s.private_state); puts("rejected");
    } else {
        assert(pc_srp_prove(&s,a,proof,m2)==-1);
        assert(pc_srp_keys(&s,key,iv)==0); assert(!s.phase && !s.private_state);
        assert(pc_srp_keys(&s,key,iv)==-1);
        hex(m2,20); putchar(' '); hex(key,16); putchar(' '); hex(iv,16); putchar('\n');
    }
    pc_srp_clear(&s); pc_srp_clear(&s); return 0;
}
