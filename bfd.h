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
#include <stdbool.h>
#include <syslog.h>
#include <netinet/ip.h>
#include "tp-timers.h"

/*
 * Format of control packet.  From section 4.1
 */
typedef struct {
  uint8_t  version      : 3;
  uint8_t  diag         : 5;

  uint8_t  state        : 2;
  uint8_t  f_poll       : 1;
  uint8_t  f_final      : 1;
  uint8_t  f_cpi        : 1;
  uint8_t  f_auth       : 1;
  uint8_t  f_demand     : 1;
  uint8_t  f_multipoint : 1;

  uint8_t  detectMult;
  uint8_t  len;
  uint32_t myDisc;
  uint32_t yourDisc;
  uint32_t desiredMinTx;
  uint32_t requiredMinRx;
  uint32_t requiredMinEcho;
} bfdCpkt;

/*
 * Session state information
 */
typedef struct _bfdSession {
  struct _bfdSession *listNext;
  struct _bfdSession *hashNext;
  struct _bfdSession *peerNext;

  /* State Variables specified in RFC 5880 */
  uint16_t SessionState       : 2;
  uint16_t RemoteSessionState : 2;
  uint16_t DemandMode         : 1;  /* we are requesting demand mode */
  uint16_t RemoteDemandMode   : 1;
  uint16_t AuthSeqKnown       : 1;
  uint16_t LocalDiag          : 5;

  uint8_t  DetectMult;
  uint8_t  AuthType;

  uint32_t LocalDiscr;
  uint32_t RemoteDiscr;
  uint32_t DesiredMinTxInterval;
  uint32_t RequiredMinRxInterval;
  uint32_t RemoteMinRxInterval;
  uint32_t RcvAuthSeq;
  uint32_t XmitAuthSeq;

  /* Other internal session data */
  uint8_t  DemandModeActive   : 1;  /* as requested by the remote system */
  uint8_t  pollSeqInProgress  : 1;  /* for sessions in Demand mode */
  uint8_t  polling            : 1;

  uint32_t activeDesiredMinTx;
  uint32_t sendDesiredMinTx;
  uint32_t detectTime;
  tpTimer  detectTimer;
  uint32_t xmtTime;
  tpTimer  xmtTimer;
  uint16_t peerPort;
  uint16_t localPort;
  struct in_addr peer;
  int sock;
} bfdSession;

/* Constants for session state */
#define BFD_STATEADMINDOWN  0
#define BFD_STATEDOWN       1
#define BFD_STATEINIT       2
#define BFD_STATEUP         3

/* Diag code constants */
#define BFD_NODIAG                  0
#define BFD_DIAG_DETECTTIMEEXPIRED  1
#define BFD_DIAG_ECHOFAILED         2
#define BFD_DIAG_NEIGHBORSAIDDOWN   3
#define BFD_DIAG_FWDPLANERESTE      4
#define BFD_DIAG_PATHDOWN           5
#define BFD_DIAG_CONCATPATHDOWN     6
#define BFD_DIAG_ADMINDOWN          7
#define BFD_DIAG_RCONCATPATHDOWNW   8

/* Various constants */
#define BFD_VERSION                1
#define BFD_DEFDEMANDMODEDESIRED   0
#define BFD_DEFDETECTMULT          2
#define BFD_DEFDESIREDMINTX        100000
#define BFD_DEFREQUIREDMINRX       50000
#define BFD_MINPKTLEN              24    /* Minimum length of control packet */
#define BFD_MINPKTLEN_AUTH         26    /* Minimum length of control packet with Auth section */
#define BFD_1HOPTTLVALUE           255
#define BFD_DOWNMINTX              1000000
#define BFD_HASHSIZE               251        /* Should be prime */
#define BFD_MKHKEY(val)            ((val) % BFD_HASHSIZE)
#define BFD_SRCPORTINIT            49142
#define BFD_SRCPORTMAX             65536
#define BFD_DEFDESTPORT            3784

/* Function prototypes */
void bfdRcvPkt(int s, void *arg);
void bfdSendCPkt(bfdSession *bfd, int fbit);
bool bfdRegisterSession(bfdSession *bfd);
void bfdStartXmtTimer(bfdSession *bfd);
void bfdRmSession(bfdSession *bfd);
int bfdRmFromList(bfdSession **list, bfdSession *bfd);
void bfdSigUsr1(int sig);
void bfdSigUsr2(int sig);
void bfdStartPollSequence(int sig);
void bfdToggleAdminDown(int sig);

#endif /* _BFD_H_ */
