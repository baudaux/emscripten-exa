#ifndef _FB_H
#define _FB_H

#define FBIOGET_VSCREENINFO	0x4600
#define FBIOPUT_VSCREENINFO	0x4601
#define FBIOGET_FSCREENINFO	0x4602
#define FBIOGETCMAP		0x4604
#define FBIOPUTCMAP		0x4605
#define FBIOPAN_DISPLAY		0x4606

struct fb_bitfield {

  uint32_t offset;           /* beginning of bitfield    */
  uint32_t length;           /* length of bitfield       */
  uint32_t msb_right;        /* != 0 : Most significant bit is */ 
};

struct fb_var_screeninfo {

  uint32_t xres;			/* visible resolution		*/
  uint32_t yres;
  uint32_t xres_virtual;		/* virtual resolution		*/
  uint32_t yres_virtual;
  uint32_t xoffset;			/* offset from virtual to visible */
  uint32_t yoffset;			/* resolution			*/

  uint32_t bits_per_pixel;		/* guess what			*/
  uint32_t grayscale;		/* 0 = color, 1 = grayscale,	*/
					/* >1 = FOURCC			*/

  struct fb_bitfield 	red;
  struct fb_bitfield 	green;
  struct fb_bitfield 	blue;
  struct fb_bitfield 	transp;

  uint32_t width;			
  uint32_t height;
	
};

struct fb_fix_screeninfo {
  
  char id[16];			/* identification string eg "TT Builtin" */
  unsigned long smem_start;	/* Start of frame buffer mem */
  /* (physical address) */
  uint32_t smem_len;			/* Length of frame buffer mem */
  uint32_t type;			/* see FB_TYPE_*		*/
  uint32_t type_aux;			/* Interleave for interleaved Planes */
  uint32_t visual;			/* see FB_VISUAL_*		*/ 
  uint16_t xpanstep;			/* zero if no hardware panning  */
  uint16_t ypanstep;			/* zero if no hardware panning  */
  uint16_t ywrapstep;		/* zero if no hardware ywrap    */
  uint32_t line_length;		/* length of a line in bytes    */
  unsigned long mmio_start;	/* Start of Memory Mapped I/O   */
  /* (physical address) */
  uint32_t mmio_len;			/* Length of Memory Mapped I/O  */
  uint32_t accel;			/* Indicate to driver which	*/
					/*  specific chip/card we have	*/
  uint16_t capabilities;		/* see FB_CAP_*			*/
  uint16_t reserved[2];		/* Reserved for future compatibility */
};

#endif // _FB_H
