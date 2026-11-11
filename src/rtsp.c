#include "picast_rtsp.h"
#include <stdio.h>
#include <string.h>

static int token(uint8_t c) {
    return (c>='a' && c<='z') || (c>='A' && c<='Z') || (c>='0' && c<='9') ||
           (c && strchr("!#$%&'*+-.^_`|~", c));
}
static int same(struct pc_span s, const char *name) {
    if (s.size != strlen(name)) return 0;
    for (size_t i=0; i<s.size; i++) {
        uint8_t a=s.data[i], b=(uint8_t)name[i];
        if (a>='A' && a<='Z') a=(uint8_t)(a+32);
        if (b>='A' && b<='Z') b=(uint8_t)(b+32);
        if (a!=b) return 0;
    }
    return 1;
}
static int decimal(struct pc_span s, uint32_t limit, uint32_t *out) {
    if (!s.size) return 0;
    uint32_t v=0;
    for (size_t i=0;i<s.size;i++) {
        if (s.data[i]<'0' || s.data[i]>'9') return 0;
        unsigned digit=s.data[i]-'0';
        if (digit>limit || v>(limit-digit)/10) return 0;
        v=v*10+digit;
    }
    *out=v; return 1;
}
int pc_rtsp_header(const struct pc_rtsp_request *r, const char *name, struct pc_span *out) {
    if (!r || !name || !out || r->header_count>PC_RTSP_HEADERS) return PC_INVALID;
    unsigned found=0; struct pc_span value={0};
    for (size_t i=0;i<r->header_count;i++) if (same(r->headers[i].name,name)) { value=r->headers[i].value; found++; }
    if (found>1) return PC_INVALID;
    *out=value; return found ? PC_OK : PC_OTHER;
}
int pc_rtsp_parse(const uint8_t *p, size_t n, struct pc_rtsp_request *out) {
    if (!out || (!p && n)) return PC_INVALID;
    size_t end=0;
    for (size_t i=0;i<n && i<PC_RTSP_HEADER_LIMIT;i++) {
        if (!p[i] || (p[i]=='\n' && (!i || p[i-1]!='\r')) ||
            (p[i]=='\r' && i+1<n && p[i+1]!='\n')) return PC_INVALID;
        if (i>=3 && !memcmp(p+i-3,"\r\n\r\n",4)) { end=i+1; break; }
    }
    if (!end) return n>=PC_RTSP_HEADER_LIMIT ? PC_INVALID : PC_OTHER;
    struct pc_rtsp_request r={0};
    size_t line=0;
    while (line+1<end && !(p[line]=='\r' && p[line+1]=='\n')) line++;
    size_t first=0; while (first<line && p[first]!=' ') first++;
    if (!first || first>24 || first==line) return PC_INVALID;
    for (size_t i=0;i<first;i++) if (!token(p[i])) return PC_INVALID;
    size_t second=first+1; while (second<line && p[second]!=' ') second++;
    if (second==first+1 || second-first-1>1024 || second==line) return PC_INVALID;
    for (size_t i=first+1;i<second;i++) if (p[i]<0x21 || p[i]>0x7e) return PC_INVALID;
    size_t version=line-second-1;
    if (version!=8) return PC_UNSUPPORTED;
    if (!memcmp(p+second+1,"HTTP/1.1",8)) r.http=1;
    else if (memcmp(p+second+1,"RTSP/1.0",8)) return PC_UNSUPPORTED;
    r.method=(struct pc_span){p,first}; r.target=(struct pc_span){p+first+1,second-first-1};
    size_t pos=line+2;
    while (pos<end-2) {
        size_t stop=pos;
        while (stop+1<end && !(p[stop]=='\r' && p[stop+1]=='\n')) stop++;
        size_t colon=pos; while (colon<stop && p[colon]!=':') colon++;
        if (colon==pos || colon==stop || r.header_count==PC_RTSP_HEADERS) return PC_INVALID;
        for (size_t i=pos;i<colon;i++) if (!token(p[i])) return PC_INVALID;
        size_t start=colon+1, last=stop;
        while (start<last && (p[start]==' ' || p[start]=='\t')) start++;
        while (last>start && (p[last-1]==' ' || p[last-1]=='\t')) last--;
        for (size_t i=start;i<last;i++) if ((p[i]<32 && p[i]!='\t') || p[i]==127) return PC_INVALID;
        r.headers[r.header_count++]=(struct pc_rtsp_header){{p+pos,colon-pos},{p+start,last-start}};
        pos=stop+2;
    }
    struct pc_span value;
    int seq=pc_rtsp_header(&r,"CSeq",&value);
    if (seq<0 || (seq==PC_OTHER && !r.http)) return PC_INVALID;
    if (seq==PC_OK) { if (!decimal(value,UINT32_MAX,&r.cseq)) return PC_INVALID; r.has_cseq=1; }
    if (pc_rtsp_header(&r,"Transfer-Encoding",&value)!=PC_OTHER) return PC_UNSUPPORTED;
    uint32_t size=0;
    int length=pc_rtsp_header(&r,"Content-Length",&value);
    if (length<0 || (length==PC_OK && !decimal(value,PC_RTSP_BODY_LIMIT,&size))) return PC_INVALID;
    if (n-end<size) return PC_OTHER;
    r.body=(struct pc_span){p+end,size}; r.consumed=end+size;
    *out=r; return PC_OK;
}
int pc_rtsp_response(const struct pc_rtsp_request *r, unsigned status, const char *type,
                     const uint8_t *body, size_t size, uint8_t *out, size_t capacity, size_t *written) {
    if (!written) return PC_INVALID;
    *written=0;
    if (!r || !out || (!body && size) || size>PC_RTSP_BODY_LIMIT) return PC_INVALID;
    const char *reason;
    switch(status) {
        case 200: reason="OK"; break;
        case 400: reason="Bad Request"; break;
        case 401: reason="Unauthorized"; break;
        case 404: reason="Not Found"; break;
        case 501: reason="Not Implemented"; break;
        default: return PC_UNSUPPORTED;
    }
    if (type && strcmp(type,"application/x-apple-binary-plist") && strcmp(type,"application/octet-stream") &&
        strcmp(type,"text/parameters")) return PC_UNSUPPORTED;
    char seq[40]="", content[100]="", header[384];
    if (r->has_cseq) snprintf(seq,sizeof(seq),"CSeq: %u\r\n",r->cseq);
    if (type) snprintf(content,sizeof(content),"Content-Type: %s\r\n",type);
    const char *server="PiCast/0.1",*public_methods="";
    int n=snprintf(header,sizeof(header),"%s %u %s\r\n%sServer: %s\r\n%s%sContent-Length: %zu\r\n\r\n",
                   r->http ? "HTTP/1.1" : "RTSP/1.0",status,reason,seq,server,public_methods,content,size);
    if (n<0 || (size_t)n>=sizeof(header) || (size_t)n>capacity || size>capacity-(size_t)n) return PC_INVALID;
    memcpy(out,header,(size_t)n); if(size) memcpy(out+n,body,size);
    *written=(size_t)n+size; return PC_OK;
}
