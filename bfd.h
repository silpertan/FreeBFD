/* Include file for Bi-directional Forwarding Detection (BFD) Protocol.
 */

#ifndef _BFD_H_
#define _BFD_H_

#include <stdint.h>
#include <stdbool.h>
#include <netinet/ip.h>

/* Program defaults */
#define BFDDFLT_DEMANDMODE      ((uint8_t)0)
#define BFDDFLT_DETECTMULT      ((uint8_t)2)
#define BFDDFLT_DESIREDMINTX    100000
#define BFDDFLT_REQUIREDMINRX   50000
#define BFDDFLT_DESTPORT        ((uint16_t)3784)

typedef enum {
  BFDSTATE_ADMINDOWN = 0,
  BFDSTATE_DOWN      = 1,
  BFDSTATE_INIT      = 2,
  BFDSTATE_UP        = 3
} bfdState;

typedef enum {
  BFD_NODIAG                 = 0,
  BFDDIAG_DETECTTIMEEXPIRED  = 1,
  BFDDIAG_ECHOFAILED         = 2,
  BFDDIAG_NEIGHBORSAIDDOWN   = 3,
  BFDDIAG_FWDPLANERESTE      = 4,
  BFDDIAG_PATHDOWN           = 5,
  BFDDIAG_CONCATPATHDOWN     = 6,
  BFDDIAG_ADMINDOWN          = 7,
  BFDDIAG_RCONCATPATHDOWNW   = 8
} bfdDiag;

typedef void* bfdSubHndl;
typedef void (*bfdSubCB)(bfdState state, void *arg);

typedef struct {
  struct in_addr PeerAddr;
  uint16_t PeerPort;
  uint16_t LocalPort;
  bool     DemandMode;
  uint8_t  DetectMult;
  uint8_t  AuthType;
  uint32_t DesiredMinTxInterval;
  uint32_t RequiredMinRxInterval;
} bfdSession;

/* Function prototypes */
bfdSubHndl bfdSubscribe(bfdSession *bfd, bfdSubCB cb, void *arg);
void bfdUnsubscribe(bfdSubHndl hndl);
bool bfdRegisterSession(bfdSession *bfd);

void bfdToggleAdminDown(int sig);
void bfdStartPollSequence(int sig);

#endif /* _BFD_H_ */
