#include <stdint.h>
#include "bfd.h"
#include "tp-timers.h"

#ifndef __BFDINT_H__
#define __BFDINT_H__

/* Various constants */
#define BFD_VERSION                1
#define BFD_MINPKTLEN              24    /* Minimum length of control packet */
#define BFD_MINPKTLEN_AUTH         26    /* Minimum length of control packet with Auth section */
#define BFD_1HOPTTLVALUE           255
#define BFD_DOWNMINTX              1000000
#define BFD_HASHSIZE               251        /* Should be prime */
#define BFD_MKHKEY(val)            ((val) % BFD_HASHSIZE)
#define BFD_SRCPORTINIT            49142
#define BFD_SRCPORTMAX             65536

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
 * Internal session state information
 */
typedef struct _bfdSession {
  bfdSession Sn; /* exactly as the user passed it in */

  struct _bfdSession *ListNext;
  struct _bfdSession *HashNext;
  struct _bfdSession *PeerNext;
  struct _bfdNotifier *notify;

  uint16_t SessionState       : 2;
  uint16_t RemoteSessionState : 2;
  uint16_t RemoteDemandMode   : 1;
  uint16_t AuthSeqKnown       : 1;
  uint16_t LocalDiag          : 5;
  uint16_t DemandModeActive   : 1;  /* as requested by the remote system */
  uint16_t PollSeqInProgress  : 1;  /* for sessions in Demand mode */
  uint16_t Polling            : 1;

  uint32_t LocalDiscr;
  uint32_t RemoteDiscr;
  uint32_t RemoteMinRxInterval;
  uint32_t RcvAuthSeq;
  uint32_t XmitAuthSeq;

  uint8_t  RefCnt;
  uint32_t ActiveDesiredMinTx;
  uint32_t SendDesiredMinTx;
  uint32_t DetectTime;
  tpTimer  DetectTimer;
  uint32_t XmtTime;
  tpTimer  XmtTimer;
  int      TxSock;
  int      RxSock;
} bfdSessionInt;

typedef struct _bfdNotifier {
  bfdSubCB             cb;
  void                *cbArg;
  bfdSessionInt       *sn;
  struct _bfdNotifier *next;
} bfdNotifier;

void bfdSendCPkt(bfdSessionInt *bfd, int fbit);
void bfdStartXmtTimer(bfdSessionInt *bfd);
void bfdRmSession(bfdSessionInt *bfd);
int bfdRmFromList(bfdSessionInt **list, bfdSessionInt *bfd);
bool bfdSocketSetup(bfdSessionInt *bfd);
bool bfdSocketClose(bfdSessionInt *bfd);
void bfdRcvPkt(int s, void *arg);

#endif /* __BFDINT_H__ */
