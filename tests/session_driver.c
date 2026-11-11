/* Typed-SETUP parser test driver: emits no peer identity or key bytes. */
#include "picast_session.h"
#include "picast.h"
#include <stdio.h>
#include <string.h>
int main(void){
    uint8_t input[4097];size_t n=fread(input,1,sizeof(input),stdin);struct pc_session_offer offer;
    memset(&offer,0xa7,sizeof(offer));
    if(pc_session_offer_parse(input,n,&offer)!=PC_OK){
        const uint8_t *p=(const uint8_t *)&offer;for(size_t i=0;i<sizeof(offer);i++)if(p[i]!=0xa7)return 4;
        return 3;
    }
    printf("{\"sender_timing_port\":%u,\"combined_info\":%u,\"wrapped_key_bytes\":72,\"iv_bytes\":16,\"media_key_decoded\":false}\n",offer.sender_timing_port,offer.combined_info);return 0;
}
