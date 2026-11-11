/* Synthetic frames only: border detection and crop decisions. */
#include "picast_crop.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { W=1920, H=884, STRIDE=1920 };
static uint8_t frame[STRIDE*1080];   /* also taller frames below */
static void paint(unsigned x,unsigned y,unsigned w,unsigned h,uint8_t value){
    for(unsigned r=y;r<y+h;r++)memset(frame+(size_t)r*STRIDE+x,value,w);
}
static int same(const struct pc_crop_box *b,unsigned x,unsigned y,unsigned w,unsigned h){
    return b->x==x && b->y==y && b->w==w && b->h==h;
}
static int feed(struct pc_crop_tracker *t,int times){
    int changed=0;struct pc_crop_box c;
    for(int i=0;i<times;i++)changed|=pc_crop_update(t,pc_crop_detect(frame,STRIDE,W,H,&c) ? NULL : &c);
    return changed;
}
int main(void){
    struct pc_crop_box c;struct pc_crop_tracker t;
    /* 16:9 picture centred in the iPhone frame, as in a fullscreen app player. */
    paint(0,0,W,H,0);paint(174,0,1572,H,128);
    assert(!pc_crop_detect(frame,STRIDE,W,H,&c) && same(&c,174,0,1572,H));
    /* Noise in a bar does not move the box; a dark top edge of the picture is seen
     * as dark (the tracker's symmetry rule keeps it from cropping, below). */
    frame[100*STRIDE+20]=200;paint(174,0,1572,40,10);paint(180,300,4,4,200);
    assert(!pc_crop_detect(frame,STRIDE,W,H,&c) && c.x==174 && c.w==1572 && c.y==40);
    {struct pc_crop_tracker e;pc_crop_reset(&e,W,H);assert(feed(&e,20) && pc_crop_is_full(&e)==0 && e.shown.y==0 && e.shown.x==174);}
    /* r235: bars at video black (16) beside a dark video whose left edge is a dim
     * blue vignette (luma 35-38) and whose right edge is brighter: crop both bars. */
    paint(0,0,W,H,16);paint(174,0,1572,H,60);paint(174,0,40,H,36);
    {struct pc_crop_tracker e;pc_crop_reset(&e,W,H);
     assert(!pc_crop_detect(frame,STRIDE,W,H,&c) && same(&c,174,0,1572,H));
     assert(feed(&e,6) && same(&e.shown,174,0,1572,H));}
    paint(0,0,W,H,0);paint(174,0,1572,H,128);
    pc_crop_reset(&t,W,H);
    assert(!feed(&t,5) && pc_crop_is_full(&t));          /* not yet: needs ~2.4 s */
    assert(feed(&t,1) && same(&t.shown,174,0,1572,H));
    /* A dark frame or a lopsided dark scene keeps the crop. */
    paint(0,0,W,H,0);
    assert(pc_crop_detect(frame,STRIDE,W,H,&c)==-1 && !feed(&t,10) && !pc_crop_is_full(&t));
    paint(174,0,1572,H,0);paint(600,0,1146,H,90);
    assert(!feed(&t,10) && same(&t.shown,174,0,1572,H));
    /* Back to a full screen (home screen): show it all within two samples. */
    paint(0,0,W,H,150);
    assert(!feed(&t,1) && feed(&t,1) && pc_crop_is_full(&t));
    /* Leaving the player for a mostly dark page: too dark to measure, but light in
     * the hidden bars brings everything back within two samples. */
    paint(0,0,W,H,0);paint(174,0,1572,H,128);pc_crop_reset(&t,W,H);feed(&t,6);
    paint(0,0,W,H,0);paint(0,20,W,30,200);
    assert(pc_crop_detect(frame,STRIDE,W,H,&c)==-1 && pc_crop_bars_lit(frame,STRIDE,W,H,&t.shown));
    {struct pc_crop_box all={0,0,W,H};assert(!pc_crop_update(&t,&all) && pc_crop_update(&t,&all) && pc_crop_is_full(&t));}
    paint(0,0,W,H,0);paint(174,0,1572,H,128);pc_crop_reset(&t,W,H);feed(&t,6);
    assert(!pc_crop_bars_lit(frame,STRIDE,W,H,&t.shown));
    /* The picture edge a few pixels into the hidden area (crop rounded to 172) is no light. */
    {struct pc_crop_box r={172,0,1576,H};assert(!pc_crop_bars_lit(frame,STRIDE,W,H,&r));}
    /* Lopsided dark content never crops from full. */
    paint(0,0,W,H,0);paint(300,0,1620,H,120);
    pc_crop_reset(&t,W,H);assert(!feed(&t,20) && pc_crop_is_full(&t));
    /* Cinemascope inside the 16:9 picture: crop both ways, even offsets. */
    paint(0,0,W,H,0);paint(174,111,1572,662,128);
    pc_crop_reset(&t,W,H);assert(feed(&t,6) && same(&t.shown,174,110,1572,664));
    /* Even dark edges that leave no usual video shape (a vignette) are picture. */
    paint(0,0,W,H,0);paint(310,0,1300,H,128);
    pc_crop_reset(&t,W,H);assert(!feed(&t,20) && pc_crop_is_full(&t));
    /* A 16:9 video reaching top and bottom loses only its side bars: nothing above
     * or below is touched. */
    paint(0,0,W,H,0);paint(174,0,1572,H,128);
    pc_crop_reset(&t,W,H);assert(feed(&t,6) && t.shown.y==0 && t.shown.h==H);
    /* A 16:9 picture with app buttons in the right bar (a control strip a quarter
     * of the height): the buttons are no picture, so it crops to the picture. */
    paint(0,0,W,H,0);paint(174,0,1572,H,128);paint(1800,300,60,220,220);
    pc_crop_reset(&t,W,H);assert(feed(&t,6) && same(&t.shown,174,0,1572,H));
    assert(!pc_crop_bars_lit(frame,STRIDE,W,H,&t.shown));
    /* A channel logo reaching from the picture's corner into the right bar (YouTube
     * watermark), no gap between: the bar is still a bar. */
    {struct pc_crop_tracker e;
     paint(0,0,W,H,16);paint(174,0,1572,H,128);paint(1716,780,60,70,200);
     pc_crop_reset(&e,W,H);assert(feed(&e,6) && same(&e.shown,174,0,1572,H));
     assert(!pc_crop_bars_lit(frame,STRIDE,W,H,&e.shown));
     /* But a picture that is lit tall into that strip is a lopsided scene: no crop. */
     paint(0,0,W,H,16);paint(174,0,1572,H,128);paint(1746,100,44,600,128);
     pc_crop_reset(&e,W,H);assert(!feed(&e,20) && pc_crop_is_full(&e));
     paint(0,0,W,H,0);paint(174,0,1572,H,128);paint(1800,300,60,220,220);}
    /* A full-width screen (the app's normal view) still shows everything. */
    paint(0,0,W,H,140);assert(!feed(&t,1) && feed(&t,1) && pc_crop_is_full(&t));
    /* A dark scene whose picture is lit only along its bottom (a table), with a
     * small button in the right bar: crop to the picture, not past its dark edge. */
    paint(0,0,W,H,0);paint(174,760,1572,124,150);paint(200,200,300,100,60);paint(1780,780,80,30,90);
    pc_crop_reset(&t,W,H);assert(feed(&t,6) && same(&t.shown,174,0,1572,H));
    /* A lit object at the dark picture's edge, tall: picture, never skipped. */
    paint(0,0,W,H,0);paint(174,0,40,H,120);paint(214,700,1532,184,150);
    assert(!pc_crop_detect(frame,STRIDE,W,H,&c) && c.x==174);
    /* Bars over a third of the frame are no letterbox. */
    paint(0,0,W,H,0);paint(800,0,320,H,128);
    assert(pc_crop_detect(frame,STRIDE,W,H,&c)==-1);
    /* Portrait screen: nothing to crop. */
    pc_crop_reset(&t,498,1080);struct pc_crop_box whole={0,0,498,1080};
    for(int i=0;i<10;i++)assert(!pc_crop_update(&t,&whole));
    assert(pc_crop_is_full(&t) && !pc_crop_update(&t,NULL));
    /* iPad (4:3) with a 16:9 video: bars above and below. */
    pc_crop_reset(&t,1440,1080);struct pc_crop_box ipad={0,135,1440,810};int moved=0;
    for(int i=0;i<6;i++)moved|=pc_crop_update(&t,&ipad);
    assert(moved && same(&t.shown,0,134,1440,812));
    /* Other display shapes: a Mac sends the shape PiCast offers for the display.
     * 21:9 display (1920x810): a 16:9 video gets side bars, a 2.39:1 film bars all
     * round; 16:10 display (1728x1080): a 16:9 video gets bars above and below. */
    {
        static const struct { unsigned w,h,x,y,cw,ch; } cases[]={
            {1920,810,240,0,1440,810},{1920,810,272,116,1376,578},{1728,1080,0,54,1728,972},
            {1920,810,240,0,1440,810}};
        for(unsigned i=0;i<sizeof(cases)/sizeof(cases[0]);i++){
            unsigned fw=cases[i].w,fh=cases[i].h;
            for(unsigned r=0;r<fh;r++)memset(frame+(size_t)r*STRIDE,16,fw);
            for(unsigned r=cases[i].y;r<cases[i].y+cases[i].ch;r++)memset(frame+(size_t)r*STRIDE+cases[i].x,i==3 ? 50 : 128,cases[i].cw);
            struct pc_crop_tracker e;pc_crop_reset(&e,fw,fh);int changed=0;
            for(int k=0;k<6;k++)changed|=pc_crop_update(&e,pc_crop_detect(frame,STRIDE,fw,fh,&c) ? NULL : &c);
            assert(changed && same(&e.shown,cases[i].x,cases[i].y,cases[i].cw,cases[i].ch));
            /* The desktop (lit to the edges) brings everything back. */
            for(unsigned r=0;r<fh;r++)memset(frame+(size_t)r*STRIDE,150,fw);
            changed=0;for(int k=0;k<2;k++)changed|=pc_crop_update(&e,pc_crop_detect(frame,STRIDE,fw,fh,&c) ? NULL : &c);
            assert(changed && pc_crop_is_full(&e));
        }
    }
    puts("crop: border detection, dark-scene hold, fast uncrop, shape and size limits passed (synthetic)");
    return 0;
}
