#include "picast_tcp.h"
#include "picast_rtsp.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include "picast_ui.h"
#ifdef __linux__
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

static void ui_show(enum pc_ui_screen screen, const char *text) {
    if (pc_ui_show(screen,text,NULL)) { /* Without a display the session continues. */ }
}
/* The PIN goes to the screen; without a framebuffer, to the text console. It is
 * never written to logs or files. */
static int show_trial_pin(const char code[5]) {
    if (!pc_ui_show(PC_UI_PIN,code,NULL)) return 0;
    int fd=open("/dev/tty1",O_WRONLY|O_NOCTTY|O_NONBLOCK);
    if (fd<0) return -1;
    char text[64];
    int n=snprintf(text,sizeof(text),"\033[2J\033[H\r\nPiCast PIN: %s\r\n",code);
    ssize_t count=write(fd,text,(size_t)n); close(fd);
    return count==n ? 0 : -1;
}

#define MAX_CONTROL_CONNECTIONS 64U
/* After pairing: back to the connecting or ready screen. */
static void clear_trial_pin(int session_running) {
    ui_show(session_running ? PC_UI_CONNECTING : PC_UI_READY,NULL);
}

static int permitted(const struct pc_tcp_diag *d,const uint8_t *ip,size_t n,int incoming){
    if(!ip || n<48 || n>1500 || ip[0]>>4!=6 || !ip[7] || 40U+((size_t)ip[4]<<8|ip[5])!=n)return 0;
    uint8_t source[16],destination[16];pc_linklocal(incoming ? d->peer : d->own,source);pc_linklocal(incoming ? d->own : d->peer,destination);
    if(memcmp(ip+8,source,16) || memcmp(ip+24,destination,16))return 0;
    unsigned server=(unsigned)ip[incoming ? 42 : 40]*256+ip[incoming ? 43 : 41];
    unsigned client=(unsigned)ip[incoming ? 40 : 42]*256+ip[incoming ? 41 : 43];
    if(ip[6]==6){
        if(n<60 || client<1024)return 0;
        size_t h=(size_t)(ip[52]>>4)*4;
        if(h<20 || h>n-40)return 0;
        if(server==37000)return 1;
        if(d->media_initialized && d->media.phase>=1 && server==37002)return 1;
        if(d->media_initialized && d->media.phase>=2 && server==37001)return 1;
    }
    if(ip[6]==17 && d->media_initialized && d->media.audio.output &&
       ((server==37004 && client>=1024) || (server==37005 && client==d->media.sender_audio_control_port)) &&
       ((size_t)ip[44]*256+ip[45])==n-40)return 1;
    if(ip[6]==17 && d->media_initialized && d->media.phase>=1 && server==37003 &&
       client==d->media.sender_timing_port && n==80 && ip[44]==0 && ip[45]==40)return 1;
    return 0;
}
int pc_tcp_diag_open(struct pc_tcp_diag *d, const uint8_t own[6], const uint8_t peer[6], const uint8_t token[16]) {
    memset(d, 0, sizeof(*d)); d->tun = d->listener = d->client = -1;
    memcpy(d->own, own, 6); memcpy(d->peer, peer, 6); memcpy(d->token, token, 16);
    int sockets[5]={-1,-1,-1,-1,-1};
    int result=pc_media_tun_open(own,&d->tun,&d->listener,sockets);
    if(!result){
        d->media_initialized=1;
        if(pc_media_open(&d->media,sockets,peer)){pc_tcp_diag_close(d);return -1;}
    }
    if (!result) {
        uint8_t seed[32];
        const char *state_dir=getenv("PICAST_STATE_DIR");
        int have_seed=state_dir && !pc_pairing_identity(state_dir,seed);
        int ok=(have_seed || RAND_bytes(seed,sizeof(seed))==1) && pc_control_init(&d->control,seed,1)==PC_OK;
        OPENSSL_cleanse(seed,sizeof(seed));
        if (!ok) { pc_tcp_diag_close(d); return -1; }
        d->control.state_dir=state_dir;
        memcpy(d->control.device_id,d->own,6); d->control_initialized=1;
        d->control.media=&d->media;
    }
    return result;
}
void pc_tcp_diag_close(struct pc_tcp_diag *d) {
    if (d->native_control && d->connections) clear_trial_pin(0);
    if(d->media_initialized)pc_media_close(&d->media);
    d->media_initialized=0;
    if (d->control_initialized) pc_control_clear(&d->control);
    d->control_initialized=0;
    if (d->client >= 0) close(d->client);
    if (d->listener >= 0) close(d->listener);
    if (d->tun >= 0) close(d->tun);
    d->client = d->listener = d->tun = -1;
}

void pc_tcp_diag_hangup(struct pc_tcp_diag *d) {
    if(d->media_initialized){
        if(d->media.video_client>=0)shutdown(d->media.video_client,SHUT_RDWR);
        if(d->media.event_client>=0)shutdown(d->media.event_client,SHUT_RDWR);
    }
    if (d->client >= 0) close(d->client);
    if (d->listener >= 0) close(d->listener);
    d->client = d->listener = -1;
}

static int message(struct pc_tcp_diag *d) {
    if (d->rtsp) {
        struct pc_rtsp_request r;
        int parsed = pc_rtsp_parse(d->rx, d->rx_n, &r);
        if (parsed != PC_OK) return parsed;
        if (!d->native_control) {
          struct pc_span token;
          if (pc_rtsp_header(&r, "X-PiCast-Token", &token) != PC_OK || token.size != 32 ||
            !r.has_cseq || r.cseq != d->messages + 1) return PC_INVALID;
          static const char digits[] = "0123456789abcdef";
          for (size_t i = 0; i < 16; i++)
            if (token.data[i*2] != digits[d->token[i]>>4] || token.data[i*2+1] != digits[d->token[i]&15]) return PC_INVALID;
        }
        if (!d->control_initialized) {
            uint8_t seed[32];
            int ok=RAND_bytes(seed,sizeof(seed))==1 && pc_control_init(&d->control,seed,1)==PC_OK;
            OPENSSL_cleanse(seed,sizeof(seed));
            if (!ok) return PC_INVALID;
            memcpy(d->control.device_id,d->own,6);
            d->control_initialized=1;
        }
        if (d->native_control) d->control.show_pin=show_trial_pin;
        size_t consumed=0;
        if (pc_control_request(&d->control,d->rx,d->rx_n,d->tx,sizeof(d->tx),&d->tx_n,&consumed)!=PC_OK ||
            consumed!=r.consumed) return PC_INVALID;
        if (d->native_control && !d->pin_cleared && d->control.phase==PC_CONTROL_VERIFIED) {
            clear_trial_pin(1);d->pin_cleared=1;
        }
        if (d->native_control) {
            const char *endpoint="other";
            const char *method="other";
            const char *methods[]={"GET","POST","OPTIONS","SETUP","RECORD","TEARDOWN","GET_PARAMETER","SET_PARAMETER"};
            for (size_t i=0;i<sizeof(methods)/sizeof(methods[0]);i++)
                if (r.method.size==strlen(methods[i]) && !memcmp(r.method.data,methods[i],r.method.size)) method=methods[i];
            const char *paths[]={"/info","/pair-setup","/pair-verify","/fp-setup","/auth-setup","/pair-pin-start","/pair-setup-pin"};
            for (size_t i=0;i<sizeof(paths)/sizeof(paths[0]);i++)
                if (r.target.size==strlen(paths[i]) && !memcmp(r.target.data,paths[i],r.target.size)) endpoint=paths[i];
            unsigned status=d->tx_n>=12 ? (unsigned)(d->tx[9]-'0')*100+(unsigned)(d->tx[10]-'0')*10+(unsigned)(d->tx[11]-'0') : 0;
            const char *media_enabled="true";
            printf("{\"event\":\"native_control_request\",\"method\":\"%s\",\"endpoint\":\"%s\",\"cseq\":%u,\"body_bytes\":%zu,\"status\":%u,\"pair_verified\":%s,\"media_path_enabled\":%s}\n",method,endpoint,r.cseq,r.body.size,status,d->control.phase==PC_CONTROL_VERIFIED ? "true" : "false",media_enabled);
        }
        d->rx_n -= r.consumed; memmove(d->rx, d->rx + r.consumed, d->rx_n);
    } else {
        if (d->rx_n < PC_TCP_MESSAGE_BYTES) return PC_OTHER;
        if (memcmp(d->rx, d->token, 16) || d->rx[16] != 0x50 || d->rx[17] != 0x43 ||
            d->rx[18] || d->rx[19] != d->messages + 1 || memcmp(d->rx + 20, "PiCast UDP probe", 16)) return PC_INVALID;
        for (size_t i=36;i<PC_TCP_MESSAGE_BYTES;i++) if (d->rx[i]!=(uint8_t)i) return PC_INVALID;
        memcpy(d->tx, d->rx, PC_TCP_MESSAGE_BYTES); d->tx_n = PC_TCP_MESSAGE_BYTES; d->rx_n = 0;
    }
    d->messages++; return PC_OK;
}
int pc_tcp_diag_step(struct pc_tcp_diag *d) {
    if(d->media_initialized && pc_media_step(&d->media))return -1;
    /* The mirror's own picture takes over, also for paired senders that showed no PIN. */
    if(d->media_initialized && d->media.phase>=2 && !d->ui_blanked){ui_show(PC_UI_BLANK,NULL);d->ui_blanked=1;}
    if (d->client < 0 && d->listener >= 0) {
        int client = accept(d->listener, NULL, NULL);
        if (client < 0) return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR ? 0 : -1;
        if (fcntl(client, F_SETFL, O_NONBLOCK) || fcntl(client, F_SETFD, FD_CLOEXEC)) { close(client); return -1; }
        d->client = client;
        d->connections++;
        /* Each PIN dialog is a connection of its own; running out would leave
         * the receiver visible but unreachable (r170). */
        if (!d->native_control || d->connections>=MAX_CONTROL_CONNECTIONS) { close(d->listener); d->listener = -1; }
    }
    if (d->client < 0) return 0;
    if (d->tx_n) {
        ssize_t n = send(d->client, d->tx + d->tx_offset, d->tx_n - d->tx_offset, MSG_NOSIGNAL);
        if (n < 0) return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR ? 0 : -1;
        if (!n) return -1;
        d->tx_offset += (size_t)n;
        if (d->tx_offset != d->tx_n) return 0;
        d->tx_n = d->tx_offset = 0;
    }
    if (d->control_initialized && d->control.phase==PC_CONTROL_CLOSED) return -1;
    if (d->messages >= (d->control_message_limit ? d->control_message_limit : d->native_control ?
128U
: 3U)) return 0;
    int parsed = message(d);
    if (parsed == PC_OK) return 0;
    if (parsed != PC_OTHER) return -1;
    size_t limit = d->rtsp ? sizeof(d->rx) : PC_TCP_MESSAGE_BYTES;
    if (d->rx_n == limit) return -1;
    ssize_t n = recv(d->client, d->rx + d->rx_n, limit - d->rx_n, 0);
    if (n < 0) return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR ? 0 : -1;
    if (!n) {
        /* The sender left a running mirror session. Ending the process is the
         * only reset that clears decoder, keys and sockets together. */
        if(d->media_initialized && d->media.phase>=2)return -1;
        if (d->native_control && !d->rx_n) {
            close(d->client); d->client=-1;
            return pc_control_reconnect(&d->control)==PC_OK ? 0 : -1;
        }
        return -1;
    }
    d->rx_n += (size_t)n;
    parsed = message(d);
    return parsed == PC_OK || parsed == PC_OTHER ? 0 : -1;
}
int pc_tcp_diag_ingress(struct pc_tcp_diag *d, const uint8_t *ip, size_t n) {
    if (!permitted(d, ip, n, 1)) return PC_OTHER;
    /* The actual kernel independently validates transport checksums and state. */
    if (write(d->tun, ip, n) != (ssize_t)n) return PC_INVALID;
    d->injected++; return PC_OK;
}
int pc_tcp_diag_read(struct pc_tcp_diag *d, uint8_t out[1501], size_t *n) {
    *n = 0;
    ssize_t got = read(d->tun, out, 1501);
    if (got < 0) return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR ? PC_OTHER : PC_INVALID;
    if (!permitted(d, out, (size_t)got, 0)) return PC_OTHER;
    d->kernel_packets++; *n = (size_t)got; return PC_OK;
}
#else
int pc_tcp_diag_open(struct pc_tcp_diag *d, const uint8_t a[6], const uint8_t b[6], const uint8_t t[16]) { (void)d; (void)a; (void)b; (void)t; return -1; }
void pc_tcp_diag_close(struct pc_tcp_diag *d) { (void)d; }
void pc_tcp_diag_hangup(struct pc_tcp_diag *d) { (void)d; }
int pc_tcp_diag_step(struct pc_tcp_diag *d) { (void)d; return -1; }
int pc_tcp_diag_ingress(struct pc_tcp_diag *d, const uint8_t *ip, size_t n) { (void)d; (void)ip; (void)n; return PC_UNSUPPORTED; }
int pc_tcp_diag_read(struct pc_tcp_diag *d, uint8_t out[1501], size_t *n) { (void)d; (void)out; (void)n; return PC_UNSUPPORTED; }
#endif
