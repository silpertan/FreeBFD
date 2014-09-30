#include <stdbool.h>

#ifndef __BFDEXTENSIONS_H__
#define __BFDEXTENSIONS_H__

typedef enum {
  BFD_EXT_SPECIFYPORTS,

  BFD_EXT_MAX
} bfdExtName;

#if (BFD_EXT_MAX > 31)
#error Too many extensions
#endif

bool bfdExtEnable(const char *ext);
bool bfdExtCheck(bfdExtName ext);
bool bfdExtDescribe(bfdExtName ext, const char** name, const char** desc);

#endif /* __BFDEXTENSIONS_H__ */
