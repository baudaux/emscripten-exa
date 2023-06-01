#ifndef _FB_H
#define _FB_H

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
	
};

#endif // _FB_H
