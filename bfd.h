/*
 * Include file for Bi-directional Forwarding Detection (BFD) Protocol.
 *
 * Author:  Tom Phelan
 *          Sonus Networks
 *          tphelan@sonusnet.com
 *
 * Copyright (c) 2003 Sonus Networks, Inc.
 */

#ifndef _BFD_H_
#define _BFD_H_

#include <stdint.h>
#include <syslog.h>
#include <netinet/ip.h>
#include "tp-timers.h"

/*
 * Format of control packet.  From section 4)
 */
typedef struct _bfdCpkt {
  uint8_t len;
  uint8_t detectMult;
  uint8_t flags;
  uint8_t diag;
  uint32_t myDisc;
  uint32_t yourDisc;
  uint32_t desiredMinTx;
  uint32_t requiredMinRx;
  uint32_t requiredMinEcho;
} bfdCpkt;

/* Macros for manipulating control packets */
#define BFD_VERMASK                   0x03
#define BFD_GETVER(diag)              ((diag) & BFD_VERMASK)
#define BFD_VERSION                   0
#define BFD_IHEARYOU                  0x01
#define BFD_DEMANDBIT                 0x02
#define BFD_PBIT                      0x04
#define BFD_FBIT                      0x08
#define BFD_DIAGNEIGHDOWN             (3 << 3)
#define BFD_DIAGDETECTTIME            (1 << 3)
#define BFD_DIAGADMINDOWN             (7 << 3)
#define BFD_SETIHEARYOU(flags, val)   {if ((val)) flags |= BFD_IHEARYOU;}
#define BFD_SETDEMANDBIT(flags, val)  {if ((val)) flags |= BFD_DEMANDBIT;}
#define BFD_SETPBIT(flags, val)       {if ((val)) flags |= BFD_PBIT;}
#define BFD_SETFBIT(flags, val)       {if ((val)) flags |= BFD_FBIT;}

/*
 * Session state information
 */
typedef struct _bfdSession {
  struct _bfdSession *listNext;
  struct _bfdSession *hashNext;
  struct _bfdSession *peerNext;
  uint8_t sessionState;
  uint8_t remoteHeard;
  uint8_t localDiag;
  uint8_t demandModeDesired;
  uint8_t demandMode;
  uint8_t pollSeqInProgress;
  uint8_t polling;
  uint8_t detectMult;
  uint8_t upDownSent;
  uint32_t localDiscr;
  uint32_t remoteDiscr;
  uint32_t desiredMinTx;
  uint32_t activeDesiredMinTx;
  uint32_t upMinTx;
  uint32_t requiredMinRx;
  uint32_t detectTime;
  tpTimer detectTimer;
  uint32_t xmtTime;
  tpTimer xmtTimer;
  struct in_addr peer;
  int sock;
} bfdSession;

/* Macros for session state */
#define BFD_STATEFAILING    0
#define BFD_STATEDOWN       1
#define BFD_STATEADMINDOWN  2
#define BFD_STATEINIT       3
#define BFD_STATEUP         4

/* Macros for debug and logging support */
extern int bfdDebug;
#define BFD_DEFDEBUG            1
#define BFD_LOGID               "bfdd"
#define bfdLog(sev, args...)    if ((sev > LOG_DEBUG) || bfdDebug) {\
                                   syslog(sev, args);\
                                }
/* Various constants */
#define BFD_DEFDEMANDMODEDESIRED   0
#define BFD_DEFDETECTMULT          2
#define BFD_DEFDESIREDMINTX        100000
#define BFD_DEFREQUIREDMINRX       50000
#define BFD_CPKTLEN                24         /* Length of control packet */
#define BFD_TTLVALUE               255
#define BFD_DOWNMINTX              1000000
#define BFD_HASHSIZE               251        /* Should be prime */
#define BFD_MKHKEY(val)            ((val) % BFD_HASHSIZE)
#define BFD_SRCPORTINIT            49142
#define BFD_SRCPORTMAX             65536
#define BFD_DEFDESTPORT            3784

/* Function prototypes */
void bfdRcvPkt(int s, void *arg);
void bfdSendCPkt(bfdSession *bfd, int fbit);
void bfdUsage(void);
void bfdDetectTimeout(tpTimer *tim, void *arg);
void bfdSessionDown(bfdSession *bfd, uint8_t diag);
void bfdSessionUp(bfdSession *bfd);
bfdSession *bfdGetSession(bfdCpkt *cp, struct sockaddr_in *sin);
bfdSession *bfdMkSession(struct in_addr peer, uint32_t remoteDisc);
void bfdXmtTimeout(tpTimer *tim, void *arg);
void bfdStartXmtTimer(bfdSession *bfd);
void bfdRmSession(bfdSession *bfd);
int bfdRmFromList(bfdSession **list, bfdSession *bfd);
void bfdSigUsr1(int sig);
void bfdSigUsr2(int sig);

#endif /* _BFD_H_ */
