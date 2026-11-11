/* Original typed decoder for the observed native mirroring SETUP offer. */
#include "picast_session.h"
#include "picast.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <plist/plist.h>
static int data(plist_t d,const char *name,uint8_t *out,size_t n){
    plist_t v=plist_dict_get_item(d,name);if(!v || plist_get_node_type(v)!=PLIST_DATA)return 0;
    uint64_t len=0;const char *p=plist_get_data_ptr(v,&len);if(!p || len!=n)return 0;memcpy(out,p,n);return 1;
}
static int number(plist_t d,const char *name,int64_t *out){
    plist_t v=plist_dict_get_item(d,name);if(!v || plist_get_node_type(v)!=PLIST_UINT)return 0;
    uint64_t value=0;plist_get_uint_val(v,&value);if(value>INT64_MAX)return 0;*out=(int64_t)value;return 1;
}
static int boolean(plist_t d,const char *name,int optional,int *out){
    plist_t v=plist_dict_get_item(d,name);if(!v)return optional;
    if(plist_get_node_type(v)!=PLIST_BOOLEAN)return 0;
    uint8_t b=0;plist_get_bool_val(v,&b);*out=b!=0;return 1;
}
int pc_session_offer_parse(const uint8_t *input,size_t n,struct pc_session_offer *out){
    if(!input || !out || n<8 || n>4096 || memcmp(input,"bplist00",8))return PC_INVALID;
    struct pc_session_offer candidate={0};int64_t et=0,port=0;int mirror=0,combined=0,ntp=0,result=PC_INVALID;
    /* Experiment (PICAST_ACCEPT_APP_VIDEO): an app's video session has no such field. */
    int app_video=getenv("PICAST_ACCEPT_APP_VIDEO")!=NULL;
    plist_t d=NULL;if(plist_from_bin((const char *)input,(uint32_t)n,&d)!=PLIST_ERR_SUCCESS || !d)return PC_INVALID;
    if(plist_get_node_type(d)!=PLIST_DICT || plist_dict_get_size(d)>32)goto done;
    plist_t protocol=plist_dict_get_item(d,"timingProtocol");uint64_t len=0;
    const char *text=protocol && plist_get_node_type(protocol)==PLIST_STRING ? plist_get_string_ptr(protocol,&len) : NULL;
    ntp=text && len==3 && !memcmp(text,"NTP",3);
    if(!ntp || !number(d,"et",&et) || et!=32 || !number(d,"timingPort",&port) || port<1 || port>65535 ||
       !boolean(d,"isScreenMirroringSession",app_video,&mirror) || (!mirror && !app_video) ||
       !boolean(d,"combinedGetInfoWithControlSetup",1,&combined) ||
       !data(d,"ekey",candidate.wrapped_key,72) || memcmp(candidate.wrapped_key,"FPLY",4) ||
       !data(d,"eiv",candidate.iv,16))goto done;
    candidate.sender_timing_port=(uint16_t)port;candidate.combined_info=(unsigned)combined;
    memcpy(out,&candidate,sizeof(candidate));result=PC_OK;
done:
    plist_free(d);
    return result;
}

void pc_session_offer_describe(const uint8_t *input,size_t n){
    plist_t d=NULL;
    if(!input || n<8 || n>4096 || plist_from_bin((const char *)input,(uint32_t)n,&d)!=PLIST_ERR_SUCCESS || !d)return;
    if(plist_get_node_type(d)==PLIST_DICT){
        plist_dict_iter it=NULL;plist_dict_new_iter(d,&it);
        /* Stream kinds decide whether an app's video could work; no value is secret. */
        plist_t streams=plist_dict_get_item(d,"streams");
        printf("{\"event\":\"native_setup_rejected\",\"stream_types\":[");
        if(streams && plist_get_node_type(streams)==PLIST_ARRAY)
            for(uint32_t i=0;i<plist_array_get_size(streams);i++){
                plist_t type=plist_dict_get_item(plist_array_get_item(streams,i),"type");uint64_t kind=0;
                if(type && plist_get_node_type(type)==PLIST_UINT)plist_get_uint_val(type,&kind);
                printf("%s%llu",i ? "," : "",(unsigned long long)kind);
            }
        printf("],\"fields\":[");
        for(unsigned first=1;it;first=0){
            char *key=NULL;plist_t value=NULL;
            plist_dict_next_item(d,it,&key,&value);
            if(!key)break;
            printf("%s\"",first ? "" : ",");
            for(const char *c=key;*c;c++)if((*c>='a' && *c<='z') || (*c>='A' && *c<='Z') || (*c>='0' && *c<='9'))putchar(*c);
            printf("\"");free(key);
        }
        free(it);
        printf("]}\n");
    }
    plist_free(d);
}
