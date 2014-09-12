/*
 * Definitions for tp-timers package.
 *
 * Author:  Tom Phelan
 *          Sonus Networks
 *          tphelan@sonusnet.com
 *
 * Copyright (c) 2003 Sonus Networks, Inc.
 */

#ifndef _TP_TIMERS_H_
#define _TP_TIMERS_H_

#include <stdint.h>
#include <signal.h>
#include <sys/time.h>

typedef struct _tpTimer {
  struct _tpTimer *next;
  struct _tpTimer *prev;
  struct timeval expiresAt;
  int running;
  void (*action)(struct _tpTimer *, void *);
  void *arg;
} tpTimer;

typedef void (*tpTimerAction)(tpTimer *, void *);

/* Socket listener stuff */
typedef void (*tpSktActor)(int, void *);

#define TP_MAXSKTS          20

/* Signal handler stuff */
typedef void (*tpSigActor)(int);
#define TP_MAXSIGNALS       (SIGUNUSED + 1)

/* Public function prototypes */
int tpSetSktActor(int skt, tpSktActor actor, void *arg, tpSktActor *old);
int tpRmSktActor(int skt);
void tpStartMsTimer(tpTimer *t, uint32_t timeout, tpTimerAction action, void *arg);
void tpStartUsTimer(tpTimer *t, uint32_t timeout, tpTimerAction action, void *arg);
void tpStartSecTimer(tpTimer *t, uint32_t timeout, tpTimerAction action, void *arg);
void tpStartTimer(tpTimer *t, struct timeval *timeout, tpTimerAction action, void *arg);
void tpStopTimer(tpTimer *t);
void tpDoEventLoop(void);
void tpInitTimers(void);
int64_t tpGetTimeRemaining(tpTimer *t);
int tpSetSignalActor(tpSigActor actor, int sig);

#ifdef TP_PRIVATE

/* Private function prototypes */
static int tpCompareTime(tpTimer *t1, tpTimer *t2);
static void tpInsertTimer(tpTimer *t);
static void tpRemoveTimer(tpTimer *t);
static void tpSubtractTime(tpTimer *t1, tpTimer *t2, struct timeval *result);
static struct timeval *tpCheckTimers(void);
static int tpTimerCompare(const void *a, const void *b, void *p);
static void tpSigHandler(int sig);

#endif  /* TP_PRIVATE */

#endif  /* _TP_TIMERS_H_ */
