#include "picast_info.h"
#include "picast_config.h"
#include "picast_identity.h"
#include <stdio.h>
#include <string.h>
#if   defined(__linux__)
#include <plist/plist.h>
#endif

/* Raw length-prefixed DNS-SD TXT requested by Apple's txtAirPlay qualifier.
 * These are our public service properties; the diagnostic token is omitted. */
static size_t info_txt(const char *device, const uint8_t pk[32],
                       const char *pairing, const char *system, uint8_t out[512]) {
    char address[32], key[68]="pk=", features[32], pi[40], psi[41];
    static const char hex[]="0123456789abcdef";
    snprintf(address,sizeof(address),"deviceid=%s",device);
    for (size_t i=0;i<32;i++) { key[3+i*2]=hex[pk[i]>>4]; key[4+i*2]=hex[pk[i]&15]; }
    key[67]=0;
    snprintf(features,sizeof(features),"features=0x%llx",(unsigned long long)pc_airplay_features());
    snprintf(pi,sizeof(pi),"pi=%s",pairing); snprintf(psi,sizeof(psi),"psi=%s",system);
    const char *fields[]={address,features,"model=" PC_AIRPLAY_MODEL,
        "srcvers=" PC_AIRPLAY_SOURCE_VERSION,"flags=0x0",key,"pw=false",
        "protovers=1.0",pi,psi,"vv=2"};
    size_t used=0;
    for (size_t i=0;i<sizeof(fields)/sizeof(*fields);i++) {
        size_t n=strlen(fields[i]);
        if (n>255 || used+1+n>512) return 0;
        out[used++]=(uint8_t)n; memcpy(out+used,fields[i],n); used+=n;
    }
    return used;
}

int pc_info_encode(const uint8_t id[6], const uint8_t pk[32], uint8_t *out, size_t cap, size_t *written) {
    if (!written) return PC_INVALID;
    *written=0;
    if (!id || !pk || !out || id[0]&1 || !memcmp(id,"\0\0\0\0\0\0",6)) return PC_INVALID;
    char device[18];
    snprintf(device,sizeof(device),"%02X:%02X:%02X:%02X:%02X:%02X",id[0],id[1],id[2],id[3],id[4],id[5]);
    int result=PC_INVALID;
    char pairing_id[37], system_id[37]; pc_airplay_pairing_id(pk,pairing_id); pc_airplay_pairing_id(pk+16,system_id);
    uint8_t txt[512]; size_t txt_n=info_txt(device,pk,pairing_id,system_id,txt);
    if (!txt_n) return PC_INVALID;
#if   defined(__linux__)
    plist_t dict=plist_new_dict(); char *data=NULL; uint32_t n=0;
    plist_t values[]={plist_new_string(pc_receiver_name()),plist_new_string(device),plist_new_string(PC_AIRPLAY_MODEL),
        plist_new_data((const char *)pk,32),plist_new_uint(pc_airplay_features()),plist_new_string(PC_AIRPLAY_SOURCE_VERSION),plist_new_uint(0),plist_new_string(pairing_id),plist_new_string(system_id),plist_new_string("1.0")
        ,plist_new_data((const char *)txt,(uint64_t)txt_n)
    };
    const char *keys[]={"name","deviceID","model","pk","features","sourceVersion","statusFlags","pi","psi","protocolVersion"
        ,"txtAirPlay"
    };
    int valid=dict!=NULL;
    size_t count=sizeof(values)/sizeof(*values);
    for (size_t i=0;i<count;i++) if (!values[i]) valid=0;
    if (valid) {
        for (size_t i=0;i<count;i++) plist_dict_set_item(dict,keys[i],values[i]);
        if (plist_dict_get_size(dict)==count && plist_to_bin(dict,&data,&n)==PLIST_ERR_SUCCESS && data && n<=cap) {
            memcpy(out,data,n); *written=n; result=PC_OK;
        }
    } else for (size_t i=0;i<count;i++) if (values[i]) plist_free(values[i]);
    if (dict) plist_free(dict);
    if (data) plist_mem_free(data);
#else
    (void)cap;
    result=PC_UNSUPPORTED;
#endif
    return result;
}
