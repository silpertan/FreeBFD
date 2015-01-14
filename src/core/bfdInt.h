#include <stdint.h>
#include <arpa/inet.h>
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
 * Macros to get/set fields of control packet. Format is from RFC5880, section 4.1.
 */
#define CPKT_GET_VERS(cp)             (cp[0] >> 5)
#define CPKT_GET_DIAG(cp)             (cp[0] & 0x1f)
#define CPKT_GET_STATE(cp)            ((unsigned char)(cp[1] >> 6))
#define CPKT_GET_POLL(cp)            ((cp[1] >> 5) & 1)
#define CPKT_GET_FINAL(cp)           ((cp[1] >> 4) & 1)
#define CPKT_GET_CPI(cp)             ((cp[1] >> 3) & 1)
#define CPKT_GET_AUTH(cp)            ((cp[1] >> 2) & 1)
#define CPKT_GET_DEMAND(cp)          ((cp[1] >> 1) & 1)
#define CPKT_GET_MULTIPOINT(cp)       (cp[1] & 1)
#define CPKT_GET_DETECT_MULT(cp)      (cp[2])
#define CPKT_GET_LEN(cp)              (cp[3])
#define CPKT_GET_MY_DISCR(cp)         ((uint32_t)(cp[4]  << 24 | cp[5]  << 16 | cp[6]  << 8  | cp[7]))
#define CPKT_GET_YOUR_DISCR(cp)       ((uint32_t)(cp[8]  << 24 | cp[9]  << 16 | cp[10] << 8  | cp[11]))
#define CPKT_GET_MIN_TX_INT(cp)       ((uint32_t)(cp[12] << 24 | cp[13] << 16 | cp[14] << 8  | cp[15]))
#define CPKT_GET_MIN_RX_INT(cp)       ((uint32_t)(cp[16] << 24 | cp[17] << 16 | cp[18] << 8  | cp[19]))
#define CPKT_GET_MIN_ECHO_RX_INT(cp)  ((uint32_t)(cp[20] << 24 | cp[21] << 16 | cp[22] << 8  | cp[23]))

#define CPKT_SET_VERS(cp,v)             { cp[0] = cp[0] & 0x1f; \
                                          cp[0] = (uint8_t)(cp[0] | ((v & 7) << 5)); }
#define CPKT_SET_DIAG(cp,v)             { cp[0] = cp[0] & 0xe0; \
                                          cp[0] = (uint8_t)(cp[0] | (v & 0x1f)); }
#define CPKT_SET_STATE(cp,v)            { cp[1] = cp[1] & 0x3f; \
                                          cp[1] = (uint8_t)(cp[1] | ((v & 3) << 6)); }
#define CPKT_SET_POLL(cp,v)             { cp[1] = v ? cp[1] | (1 << 5) : cp[1] & 0xdf; }
#define CPKT_SET_FINAL(cp,v)            { cp[1] = v ? cp[1] | (1 << 4) : cp[1] & 0xef; }
#define CPKT_SET_CPI(cp,v)              { cp[1] = v ? cp[1] | (1 << 3) : cp[1] & 0xf7; }
#define CPKT_SET_AUTH(cp,v)             { cp[1] = v ? cp[1] | (1 << 2) : cp[1] & 0xfb; }
#define CPKT_SET_DEMAND(cp,v)           { cp[1] = v ? cp[1] | (1 << 1) : cp[1] & 0xfd; }
#define CPKT_SET_MULTIPOINT(cp,v)       { cp[1] = v ? cp[1] |  1       : cp[1] & 0xfe; }
#define CPKT_SET_DETECT_MULT(cp,v)      { cp[2] = (v & 0xff); }
#define CPKT_SET_LEN(cp,v)              { cp[3] = (v & 0xff); }
#define CPKT_SET_WORD(cp,vv,i)          { cp[i]   = (uint8_t)( vv >> 24);         \
                                          cp[i+1] = (uint8_t)((vv >> 16) & 0xff); \
                                          cp[i+2] = (uint8_t)((vv >> 8)  & 0xff); \
                                          cp[i+3] = (uint8_t)( vv & 0xff); }
#define CPKT_SET_MY_DISCR(cp,v)         CPKT_SET_WORD(cp,v,4)
#define CPKT_SET_YOUR_DISCR(cp,v)       CPKT_SET_WORD(cp,v,8)
#define CPKT_SET_MIN_TX_INT(cp,v)       CPKT_SET_WORD(cp,v,12)
#define CPKT_SET_MIN_RX_INT(cp,v)       CPKT_SET_WORD(cp,v,16)
#define CPKT_SET_MIN_ECHO_RX_INT(cp,v)  CPKT_SET_WORD(cp,v,20)

/*
 * Internal session state information
 */
typedef struct _bfdSession {
  bfdSession Sn; /* exactly as the user passed it in */

  struct _bfdSession *ListNext;
  struct _bfdSession *HashNext;
  struct _bfdSession *PeerNext;
  struct _bfdNotifier *notify;

  uint8_t SessionState;
  uint8_t RemoteSessionState;
  bool    RemoteDemandMode;
  bool    AuthSeqKnown;
  uint8_t LocalDiag;
  bool    DemandModeActive;  /* as requested by the remote system */
  bool    PollSeqInProgress;  /* for sessions in Demand mode */
  bool    Polling;

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
