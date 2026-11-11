#include "picast_trace.h"
#include "picast.h"
#include <assert.h>
#include <string.h>
int main(void) {
    uint8_t packet[128]={0};
    for(int soft=0;soft<=1;soft++) {
        FILE *f=tmpfile();assert(f);
        struct pc_trace t={0};assert(pc_trace_init(&t,f,200,soft)==PC_OK);
        assert(pc_trace_write(&t,1,0,packet,sizeof(packet))==PC_OK && t.bytes==168);
        assert(pc_trace_write(&t,1,1000000,packet,1)==PC_INVALID && t.bytes==168);
        int rc=pc_trace_write(&t,2,0,packet,sizeof(packet));
        assert(rc==(soft ? PC_OK : PC_INVALID) && t.bytes==168);
        if(soft){
            /* Smaller later packets must not create holes in the prefix. */
            for(unsigned i=0;i<100000;i++)assert(pc_trace_write(&t,3,0,packet,1)==PC_OK);
            assert(t.skipped==100001 && t.saturated && t.bytes==168);
        }
        assert(!fflush(f) && ftell(f)==168);rewind(f);
        uint8_t contents[168];assert(fread(contents,1,sizeof(contents),f)==sizeof(contents));
        assert(contents[0]==0xd4 && contents[24]==1 && contents[40]==0);
        assert(!fclose(f));
    }
    puts("trace: hard bound, soft saturation, contiguous prefix and fixed storage across100000 packets passed");
}
