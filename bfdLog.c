#include <stdarg.h>
#include <syslog.h>
#include "bfdLog.h"

#define BFD_LOGID          "bfdd"

#ifdef BFD_LOGTOSTDERR
#define BFD_LOGFLAG LOG_PERROR
#endif 

static int sMaxLevel = LOG_WARNING;

void bfdLogInit(void)
{
  openlog(BFD_LOGID, LOG_PID | BFD_LOGFLAG, LOG_DAEMON);
}

void bfdLogMore(void)
{
  if (sMaxLevel < LOG_DEBUG) {
    sMaxLevel++;
  }
}

void bfdLog(int lvl, const char *fmt, ...)
{
  if (lvl <= sMaxLevel) {
    va_list ap;

    va_start(ap, fmt);
    vsyslog(lvl, fmt, ap);
    va_end(ap);
  }
}
