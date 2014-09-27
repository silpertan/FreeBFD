/* Timer and socket support routines.  This module uses an event
 * model.  There are two types of objects that generate events - timers and sockets.
 * Timers generate an event when they expire.  Sockets generate an event when there
 * is data available to read.
 *
 * Applications using this module should open intial sockets and set the socket
 * actor routines (using timSetSktActor), optionally start timers, and then call
 * timDoEventLoop.  timDoEventLoop never returns, but calls the appropriate socket
 * actor or timer actor routines when the events occur.
 */

#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/time.h>
#include "avl.h"
#define TP_PRIVATE
#include "tp-timers.h"

/*
 * Active timers are kept in an AVL tree (also known as a balanced binary tree).
 * This tree is sorted by expiration time, that is, the "first" node in the tree
 * (not the same as the root node) is the timer that will expire first.  The
 * advantage of AVL trees is that the worst case insertion, deletion and search
 * is proportional to the log, base 2, of the number of nodes.  That makes it very
 * efficient for managing a large number of items, and should allow us to connect
 * to tens of thousands of MTAs without significant performance impact.
 *
 * The AVL trees are implemented using the GNU libavl.  Documentation is in
 * avl-1.4.0/avl.html.
 */
static avl_tree *timerTree;

static tpSktActor sktActors[TP_MAXSKTS];
static void *sktArgs[TP_MAXSKTS];
static fd_set sktSet;
static int maxSkt;

static int caughtSignal;
static sigset_t caughtSigset;
static sigset_t activeSigset;
static tpSigActor sigActors[TP_MAXSIGNALS];

/*
 * tpSetSktActor - set the socket actor function for a given socket.
 *
 * Parameters:      skt - the socket.
 *                  actor - the socket actor function.
 *                  arg - an argument to send to the actor function.
 *                  old - a place to return the old socket actor (if not NULL).
 *
 * Returns:         <0 on error (errno set).
 *
 * Side effects:    When there is read data in the socket, the actor function
 *                  will be called.
 */
int tpSetSktActor(int skt, tpSktActor actor, void *arg, tpSktActor *old)
{
  if (skt >= TP_MAXSKTS || skt < 0) {
    errno = EBADF;
    return(-1);
  }
  if (old != NULL) {
    *old = sktActors[skt];
  }
  sktActors[skt] = actor;
  sktArgs[skt] = arg;
  FD_SET(skt, &sktSet);
  if (skt >= maxSkt) {
    maxSkt = skt + 1;
  }
  return(0);
}

/*
 * tpRmSktActor - remove the current actor function for a socket.
 *
 * Parameters:     skt - the socket.
 *
 * Returns:        <0 on error (errno set).
 *
 * Side effects:   If the socket has read data, no actor function will be called.
 */
int tpRmSktActor(int skt)
{
  if (skt >= TP_MAXSKTS || skt < 0) {
    errno = EBADF;
    return(-1);
  }
  sktActors[skt] = NULL;
  sktArgs[skt] = NULL;
  FD_CLR(skt, &sktSet);
  return(0);
}

/*
 * tpSetSignalActor - set actor function for EINTR actions
 *
 * Parameters:        actor - actor function to set
 *
 * Returns:           0 always
 */
int tpSetSignalActor(tpSigActor actor, int sig)
{
  struct sigaction sa;

  if (sig >= TP_MAXSIGNALS) {
    return(-1);
  }
  sigActors[sig] = actor;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = tpSigHandler;
  sigaction(sig, &sa, NULL);
  return(0);
}

static void tpSigHandler(int sig)
{
  caughtSignal = 1;
  sigaddset(&caughtSigset, sig);
}

/*
 * tpCompareTime - compare the exipration of two timers.
 *
 * Parameters:      t1, t2 - the timers to compare.
 *
 * Returns:         -1 - t1 will expire before t2.
 *                  0  - t1 and t2 expire simultaneously.
 *                  1  - t1 expires after t2.
 */
static int tpCompareTime(tpTimer *t1, tpTimer *t2)
{
  if (t1->expiresAt.tv_sec < t2->expiresAt.tv_sec) {
    return(-1);
  }
  if (t1->expiresAt.tv_sec > t2->expiresAt.tv_sec) {
    return(1);
  }
  if (t1->expiresAt.tv_usec < t2->expiresAt.tv_usec) {
    return(-1);
  }
  if (t1->expiresAt.tv_usec > t2->expiresAt.tv_usec) {
    return(1);
  }
  return(0);
}

/*
 * tpInsertTimer - insert a timer into the AVL tree.
 */
static void tpInsertTimer(tpTimer *t)
{
  avl_insert(timerTree, (void *)t);
}

/*
 * tpRemoveTimer - remove a timer from the AVL tree.
 */
static void tpRemoveTimer(tpTimer *t)
{
  avl_delete(timerTree, (void *)t);
}

/*
 * tpSubtractTime - get difference bewteen two times.
 *
 * Parameters:       t1, t2 - timers with expiration times to subtract.
 *                   result - timeval to contain result.
 *
 * Returns:          nothing.
 *
 * Side effects:     result = t1->expiresAt - t2->expiresAt.
 */
static void tpSubtractTime(tpTimer *t1, tpTimer *t2, struct timeval *result)
{
  if ((t2->expiresAt.tv_sec > t1->expiresAt.tv_sec) ||
      ((t2->expiresAt.tv_sec == t1->expiresAt.tv_sec) &&
       (t2->expiresAt.tv_usec >= t1->expiresAt.tv_usec))) {
    result->tv_sec = 0;
    result->tv_usec = 0;
    return;
  }
  if (t2->expiresAt.tv_usec > t1->expiresAt.tv_usec) {
    /* Need to do borrow */
    result->tv_sec = t1->expiresAt.tv_sec - 1;
    result->tv_usec = t1->expiresAt.tv_usec + 1000000;
  } else {
    result->tv_sec = t1->expiresAt.tv_sec;
    result->tv_usec = t1->expiresAt.tv_usec;
  }
  result->tv_usec -= t2->expiresAt.tv_usec;
  result->tv_sec -= t2->expiresAt.tv_sec;
}

/*
 * tpStartMsTimer - start a timer with timeout in milliseconds.
 *
 * Parameters:       t - timer to start.
 *                   timeout - timeout value in milliseconds.
 *                   action - actor function for timer.
 *                   arg - argument for actor function.
 *
 * Returns:          nothing.
 *
 * Side effects:     'action' will be called in 'timeout' milliseconds.
 */
void tpStartMsTimer(tpTimer *t, uint32_t timeout,
                   tpTimerAction action, void *arg)
{
  struct timeval tv;

  tv.tv_sec = timeout/1000;
  tv.tv_usec = (timeout % 1000)*1000;
  tpStartTimer(t, &tv, action, arg);
}

/*
 * tpStartUsTimer - start a timer with timeout in microseconds.
 *
 * Parameters:       t - timer to start.
 *                   timeout - timeout value in microseconds.
 *                   action - actor function for timer.
 *                   arg - argument for actor function.
 *
 * Returns:          nothing.
 *
 * Side effects:     'action' will be called in 'timeout' microseconds.
 */
void tpStartUsTimer(tpTimer *t, uint32_t timeout,
                   tpTimerAction action, void *arg)
{
  struct timeval tv;

  tv.tv_sec = timeout/1000000;
  tv.tv_usec = timeout % 1000000;
  tpStartTimer(t, &tv, action, arg);
}

/*
 * tpStartSecTimer - start a timer with timeout in seconds.
 *
 * Parameters:        t - timer to start.
 *                    timeout - timeout value in seconds.
 *                    action - actor function for timer.
 *                    arg - argument for actor function.
 *
 * Returns:           nothing.
 *
 * Side effects:      'action' will be called in 'timeout' seconds.
 */
void tpStartSecTimer(tpTimer *t, uint32_t timeout,
                   tpTimerAction action, void *arg)
{
  struct timeval tv;

  tv.tv_sec = timeout;
  tv.tv_usec = 0;
  tpStartTimer(t, &tv, action, arg);
}

/*
 * tpStartTimer - start a timer with timeout in 'struct timeval'
 *                 (microsecond granularity).
 *
 * Parameters:     t - timer to start.
 *                 timeout - timeout value in seconds and microseconds.
 *                 action - actor function for timer.
 *                 arg - argument for actor function.
 *
 * Side effects:   'action' will be called in 'timeout' seconds and microseconds.
 */
void tpStartTimer(tpTimer *t, struct timeval *timeout,
                tpTimerAction action, void *arg)
{
  struct timeval now;

  if (t->running) {
    tpStopTimer(t);
  }
  gettimeofday(&now, NULL);
  t->expiresAt.tv_usec = now.tv_usec + timeout->tv_usec;
  t->expiresAt.tv_sec = now.tv_sec + timeout->tv_sec;
  if (t->expiresAt.tv_usec > 1000000) {
    t->expiresAt.tv_sec += t->expiresAt.tv_usec/1000000;
    t->expiresAt.tv_usec %= 1000000;
  }
  t->action = action;
  t->arg = arg;
  t->running = 1;
  tpInsertTimer(t);
}

/*
 * tpStopTimer - stop a timer.
 *
 * Parameters:    t - timer to stop.
 *
 * Returns:       nothing.
 *
 * Side effects:  actor function for timer will not be called.
 */
void tpStopTimer(tpTimer *t)
{
  if (t->running) {
    tpRemoveTimer(t);
    t->running = 0;
  }
}

/*
 * tpGetTimeRemaining - get time until timer expires.
 *
 * Parameters:          t - timer to check
 *
 * Returns:             microseconds until timer expires.
 *                      -1 if timer not running.
 */
int64_t tpGetTimeRemaining(tpTimer *t)
{
  struct timeval now;

  if (!t->running) return(-1);
  gettimeofday(&now, NULL);
  if (now.tv_sec > t->expiresAt.tv_sec) {
    return(0);
  } else if ((now.tv_sec == t->expiresAt.tv_sec) &&
             (now.tv_usec > t->expiresAt.tv_usec)) {
    return(0);
  }
  now.tv_sec = t->expiresAt.tv_sec - now.tv_sec;
  now.tv_usec = t->expiresAt.tv_usec - now.tv_usec;
  return((now.tv_sec*1000000) + now.tv_usec);
}

/*
 * tpCheckTimers - check for expired timers.
 *
 * Returns:         Time until next unexpired timer will expire.
 *                  NULL if no timers are active.
 *
 * Side effects:    Calls actor functions for timers that have reached
 *                  expiration time.  Removes expired timers from AVL tree.
 */
static struct timeval *tpCheckTimers(void)
{
  avl_traverser trav = AVL_TRAVERSER_INIT;
  tpTimer now, *t;
  static struct timeval nextExpire;

  gettimeofday(&(now.expiresAt), NULL);
  while ((t = (tpTimer *)avl_traverse(timerTree, &trav)) != NULL) {
    if (tpCompareTime(t, &now) <= 0) {
      /* Timer has expired */
      t->running = 0;
      tpRemoveTimer(t);
      t->action(t, t->arg);
    } else {
      /* No more timers to expire */
      break;
    }
    avl_init_traverser(&trav);
  }
  if (t != NULL) {
    /* Calculate time until next timer expires */
    gettimeofday(&(now.expiresAt), NULL);
    tpSubtractTime(t, &now, &nextExpire);
    return(&nextExpire);
  } else {
    return(NULL);
  }
}

static void tpCheckSignals(void)
{
  int i;

  sigprocmask(SIG_BLOCK, &activeSigset, NULL);
  if (caughtSignal) {
    for (i = 0; i < TP_MAXSIGNALS; ++i) {
      if (sigismember(&caughtSigset, i) && sigActors[i]) {
        sigActors[i](i);
      }
    }
    sigemptyset(&caughtSigset);
    caughtSignal = 0;
  }
  sigprocmask(SIG_UNBLOCK, &activeSigset, NULL);
}

/*
 * tpDoEventLoop - monitor for events and call actor functions.
 *
 * Comments:        Never returns.
 */
void tpDoEventLoop(void)
{
  fd_set rdset;
  int n, i;
  struct timeval *nextTimer;

  /* Receive and respond to events */
  while (1) {
    /* Check for expired timers */
    nextTimer = tpCheckTimers();
    /* Check for signals */
    tpCheckSignals();
    /*
     * Use 'select' to wait until the next timer expires (time untill next
     * timer is in 'nextTimer', NULL if no timers are active), or until
     * some of the sockets have read data available.
     */
    memcpy(&rdset, &sktSet, sizeof(rdset));
    if ((n = select(maxSkt, &rdset, NULL, NULL, nextTimer)) > 0) {
      /* Some sockets have data, find which ones */
      for (i = 0; i < TP_MAXSKTS; ++i) {
        if (FD_ISSET(i, &rdset)) {
          if (sktActors[i] != NULL) {
            sktActors[i](i, sktArgs[i]);
          }
          if (--n <= 0) break;
        }
      }
    }
  }
}

/*
 * tpTimerCompare - compare expiration time of two timers.
 *
 * Parameters:       a, b - timers to compare.
 *                   p - unused.
 *
 * Returns:          -1, 0, 1 - for 'a' expiration time less than, equal to,
 *                   or greater than 'b', respectively.
 *
 * Comments:         Used by AVL library as avl_comparison_function.
 */
static int tpTimerCompare(const void *a, const void *b, void *p)
{
  return(tpCompareTime((tpTimer *)a, (tpTimer *)b));
}

/*
 * tpInitTimers - initialize the timers package.
 *
 * Comments:       Must be called before any timer or socket functions
 *                 can be used.
 */
void tpInitTimers(void)
{
  timerTree = avl_create(tpTimerCompare, NULL);
}
