#include <stdarg.h>
#include <syslog.h>
#include <stdlib.h>
#include "bfdLog.h"

#ifdef BFD_LOGTOSTDERR
#define BFD_LOGFLAG LOG_PERROR
#endif 

static int sMaxLevel = LOG_NOTICE;

void bfdLogInit(void)
{
  openlog(NULL, LOG_PID | BFD_LOGFLAG, LOG_DAEMON);
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
