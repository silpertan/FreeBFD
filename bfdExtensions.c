#include <string.h>
#include <stdint.h>
#include "bfdExtensions.h"

typedef struct {
  const char* name;
  const char* desc;
} bfdExtension;

const bfdExtension extensions[] = {
  [BFD_EXT_SPECIFYPORTS] = {
    "SpecifyPorts",
    "Specify non-standard UDP src/dst ports"
  },
};

static uint32_t enabled = 0;

bool bfdExtEnable(const char *ext)
{
  uint8_t idx;

  if (!ext) { return false; }

  for (idx = 0;
       idx < sizeof(extensions) / sizeof(bfdExtension);
       idx++)
  {
    if (strncmp(extensions[idx].name, ext, strlen(extensions[idx].name)) == 0)
    {
      enabled |= (uint32_t)(1 << idx);
      return true;
    }
  }

  return false;
}

bool bfdExtCheck(bfdExtName ext)
{
  return enabled & (uint32_t)(1 << ext);
}

bool bfdExtDescribe(bfdExtName ext, const char** name, const char** desc)
{
  if (ext < BFD_EXT_MAX) {
    *name = extensions[ext].name;
    *desc = extensions[ext].desc;
    return true;
  }

  return false;
}
