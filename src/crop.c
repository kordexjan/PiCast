/* Original black-border detection and crop decision for mirrored video. */
#include "picast_crop.h"
#include <string.h>

/* iOS draws its bars at video black, luma 16, and compression adds only a few
 * codes on such a flat area. A dark picture edge sits barely above: the blue
 * vignette of a dark video measured 35 to 38 (r235), so a bar must be close to
 * 16. Showing more again needs real light (PC_CROP_LIT), not a dim edge. */
#define PC_CROP_BLACK 24
#define PC_CROP_LIT 40
#define PC_CROP_STEP 8
/* Detections are taken about every 0.4 s: show more after ~0.8 s, crop after ~2.4 s,
 * so dark scenes and briefly shown controls do not make the picture jump. */
#define PC_CROP_GROW_AGREE 2
#define PC_CROP_SHRINK_AGREE 6

static int row_below(const uint8_t *luma,size_t stride,unsigned y,unsigned width,unsigned level){
    const uint8_t *row=luma+(size_t)y*stride;unsigned bright=0;
    for(unsigned x=PC_CROP_STEP/2;x<width;x+=PC_CROP_STEP)if(row[x]>level && ++bright>2)return 0;
    return 1;
}
static int row_dark(const uint8_t *luma,size_t stride,unsigned y,unsigned width){return row_below(luma,stride,y,width,PC_CROP_BLACK);}
static int column_dark(const uint8_t *luma,size_t stride,unsigned x,unsigned top,unsigned bottom){
    unsigned bright=0;
    for(unsigned y=top;y<bottom;y+=PC_CROP_STEP)if(luma[(size_t)y*stride+x]>PC_CROP_BLACK && ++bright>2)return 0;
    return 1;
}
/* Apps put buttons beside a fullscreen picture (a close cross, a control strip, a
 * subscribe button). Such a button is narrow, short and stands apart from the
 * picture by a dark gap, while the picture's own edge may be dark nearly all the
 * way down (a dark scene with a lit table at the bottom). So skip lit clusters
 * that are narrow, under half the height and followed by a gap; everything else is picture. */
#define PC_CROP_BUTTON_GAP 6
static int short_cluster(const uint8_t *luma,size_t stride,unsigned x0,unsigned x1,unsigned top,unsigned bottom){
    unsigned first=bottom,last=top;
    for(unsigned x=x0;x<x1;x+=2)
        for(unsigned y=top;y<bottom;y+=PC_CROP_STEP)
            if(luma[(size_t)y*stride+x]>PC_CROP_BLACK){if(y<first)first=y;if(y>last)last=y;}
    return first>=last || (last-first)*2<bottom-top;
}
/* Width of the dark margin from one side (from_right set: the right side). */
static unsigned margin(const uint8_t *luma,size_t stride,unsigned width,unsigned top,unsigned bottom,int from_right){
    unsigned limit=width/3,i=0;
#define COL(k) (from_right ? width-1-(k) : (k))
    while(i<limit){
        if(column_dark(luma,stride,COL(i),top,bottom)){i++;continue;}
        unsigned start=i;
        while(i<limit && !column_dark(luma,stride,COL(i),top,bottom))i++;
        unsigned end=i,gap=i;
        while(gap<limit && column_dark(luma,stride,COL(gap),top,bottom))gap++;
        unsigned x0=from_right ? width-end : start,x1=from_right ? width-start : end;
        if(end-start<=width/10 && gap-end>=PC_CROP_BUTTON_GAP && gap<limit && short_cluster(luma,stride,x0,x1,top,bottom)){i=gap;continue;}
        return start;
    }
#undef COL
    return limit;
}
int pc_crop_detect(const uint8_t *luma,size_t stride,unsigned width,unsigned height,struct pc_crop_box *content){
    if(!luma || !content || width<64 || height<64 || stride<width)return -1;
    /* A bar wider than a third of the frame is no letterbox; stopping there also
     * bounds the time spent on a dark frame. */
    unsigned top=0,bottom=height,left=0,right=width,ly=height/3,lx=width/3;
    while(top<ly && row_dark(luma,stride,top,width))top++;
    while(height-bottom<ly && row_dark(luma,stride,bottom-1,width))bottom--;
    if(top==ly || height-bottom==ly)return -1;
    left=margin(luma,stride,width,top,bottom,0);
    right=width-margin(luma,stride,width,top,bottom,1);
    if(left==lx || width-right==lx)return -1;
    /* A channel logo or button may reach from the picture into one bar (YouTube's
     * watermark at the player's corner), with no gap to skip. iOS centres the
     * picture, so when one side's margin is wider, the extra strip on the other
     * side is bar if all its light is short; the picture's own edge, a few pixels
     * into the strip, is left out. Only sideways: a lit bottom bar uncrops anyway. */
    {
        unsigned ml=left,mr=width-right;
        if(ml>mr+16 && ml-mr<=width/10 && short_cluster(luma,stride,width-ml+PC_CROP_STEP,width-mr,top,bottom))right=width-ml;
        else if(mr>ml+16 && mr-ml<=width/10 && short_cluster(luma,stride,ml,mr-PC_CROP_STEP,top,bottom))left=mr;
    }
    content->x=left;content->y=top;content->w=right-left;content->h=bottom-top;
    return 0;
}

static int column_lit(const uint8_t *luma,size_t stride,unsigned x,unsigned height){
    unsigned bright=0;
    for(unsigned y=PC_CROP_STEP/2;y<height;y+=PC_CROP_STEP)if(luma[(size_t)y*stride+x]>PC_CROP_LIT && ++bright>2)return 1;
    return 0;
}
int pc_crop_bars_lit(const uint8_t *luma,size_t stride,unsigned width,unsigned height,const struct pc_crop_box *shown){
    if(!luma || !shown || shown->x+shown->w>width || shown->y+shown->h>height)return 0;
    /* The picture's own edge may sit a few pixels inside the hidden area (the crop
     * is rounded and symmetric), so only look further out than that. */
    const unsigned edge=PC_CROP_STEP;
    for(unsigned y=0;y+edge<shown->y;y+=2)if(!row_below(luma,stride,y,width,PC_CROP_LIT))return 1;
    for(unsigned y=shown->y+shown->h+edge;y<height;y+=2)if(!row_below(luma,stride,y,width,PC_CROP_LIT))return 1;
    /* Beside the picture, light on one side only is an app's buttons; light on both
     * sides (a toolbar across the screen) means the app left its player. */
    int left=0,right=0;
    for(unsigned x=0;x+edge<shown->x && !left;x+=2)left=column_lit(luma,stride,x,height);
    for(unsigned x=shown->x+shown->w+edge;x<width && !right;x+=2)right=column_lit(luma,stride,x,height);
    return left && right;
}
static unsigned diff(unsigned a,unsigned b){return a>b ? a-b : b-a;}
static int near(const struct pc_crop_box *a,const struct pc_crop_box *b,unsigned slack){
    return diff(a->x,b->x)<=slack && diff(a->y,b->y)<=slack && diff(a->x+a->w,b->x+b->w)<=slack && diff(a->y+a->h,b->y+b->h)<=slack;
}
static int inside(const struct pc_crop_box *in,const struct pc_crop_box *out,unsigned slack){
    return in->x+slack>=out->x && in->y+slack>=out->y && in->x+in->w<=out->x+out->w+slack && in->y+in->h<=out->y+out->h+slack;
}
/* 4:3, 16:9, 1.85:1, 2:1, 2.35:1 and 2.39:1, each within 2 %. */
static int video_shape(unsigned w,unsigned h){
    static const unsigned shapes[]={1333,1778,1850,2000,2350,2390};
    if(!h)return 0;
    unsigned long r=(unsigned long)w*1000/h;
    for(unsigned i=0;i<sizeof(shapes)/sizeof(shapes[0]);i++)
        if(r*100>=shapes[i]*98UL && r*100<=shapes[i]*102UL)return 1;
    return 0;
}
void pc_crop_reset(struct pc_crop_tracker *t,unsigned width,unsigned height){
    memset(t,0,sizeof(*t));t->width=width;t->height=height;
    t->shown=(struct pc_crop_box){0,0,width,height};t->pending=t->shown;
}
int pc_crop_is_full(const struct pc_crop_tracker *t){
    return t->shown.x==0 && t->shown.y==0 && t->shown.w==t->width && t->shown.h==t->height;
}
int pc_crop_update(struct pc_crop_tracker *t,const struct pc_crop_box *c){
    if(!t->width || !t->height)return 0;
    if(!c || c->x+c->w>t->width || c->y+c->h>t->height){t->agree=0;return 0;}
    struct pc_crop_box full={0,0,t->width,t->height},target=full;
    unsigned left=c->x,right=t->width-(c->x+c->w),top=c->y,bottom=t->height-(c->y+c->h);
    /* Each axis on its own: iOS centres the picture, so equal bars are bars, while
     * darkness on one side only is a scene. Such a scene keeps the margin already
     * shown on that axis rather than opening it. */
    unsigned mx=0,my=0;
    if(diff(left,right)<=16)mx=(left<right ? left : right)&~1U;
    else if(left+4>=t->shown.x && right+4>=t->width-(t->shown.x+t->shown.w))mx=t->shown.x;
    if(diff(top,bottom)<=16)my=(top<bottom ? top : bottom)&~1U;
    else if(top+4>=t->shown.y && bottom+4>=t->height-(t->shown.y+t->shown.h))my=t->shown.y;
    if(mx<8)mx=0;
    if(my<8)my=0;
    target=(struct pc_crop_box){mx,my,t->width-2*mx,t->height-2*my};
    /* Only black is ever removed, never picture: a crop must leave a usual video
     * shape. A dark scene with even edges (a vignette) rarely does, and then the
     * picture stays as it is. */
    if(!near(&target,&full,0) && !video_shape(target.w,target.h))target=t->shown;
    if(near(&target,&t->shown,4)){t->agree=0;return 0;}
    unsigned need=inside(&target,&t->shown,4) ? PC_CROP_SHRINK_AGREE : PC_CROP_GROW_AGREE;
    if(t->agree && near(&target,&t->pending,8))t->agree++;
    else t->agree=1;
    t->pending=target;
    if(t->agree<need)return 0;
    t->shown=target;t->agree=0;return 1;
}
