/* This file implements the Bi-drectional Forwarding Detection (BFD) Protocol
 * with IPv4 single-hop encapsulation, as described RFC 5880 and RFC 5881.
 */

#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include "bfd.h"
#include "tp-timers.h"
#include "bfdLog.h"

#define UNUSED(x) { if(x){} }

static bfdSession *sessionList;                  /* List of active sessions */
static bfdSession *sessionHash[BFD_HASHSIZE];    /* Find session from discriminator */
static bfdSession *peerHash[BFD_HASHSIZE];       /* Find session from peer address */

static bfdSession *bfdGetSession(bfdCpkt *cp, struct sockaddr_in *sin);
static void bfdXmtTimeout(tpTimer *tim, void *arg);
static void bfdSessionDown(bfdSession *bfd, uint8_t diag);
static void bfdSessionUp(bfdSession *bfd);
static void bfdDetectTimeout(tpTimer *tim, void *arg);
static bool bfdSetupRcvSocket(bfdSession *bfd);

/*
 * All received packets come through here.
 */
void bfdRcvPkt(int s, void *arg)
{
  struct msghdr *msg = (struct msghdr *)arg;
  ssize_t mlen;
  struct sockaddr_in *sin;
  bfdCpkt *cp;
  struct cmsghdr *cm;
  bfdSession *bfd;
  uint32_t oldXmtTime;
  bool goodTTL = false;
  bool sendPkt = false;

  /* Get packet */
  if ((mlen = recvmsg(s, msg, 0)) < 0) {
    struct sockaddr_in tmp;
    socklen_t tmp_len = sizeof(struct sockaddr_in);

    getsockname(s, (struct sockaddr*)&tmp, &tmp_len);
    bfdLog(LOG_ERR, "Error receiving from BFD socket %s:%d: %m\n",
           inet_ntoa(tmp.sin_addr), ntohs(tmp.sin_port));
    return;
  }

  /* Get source address */
  sin = (struct sockaddr_in *)(msg->msg_name);

  /* Get and check TTL */
  for (cm = CMSG_FIRSTHDR(msg);
       cm != NULL;
       cm = CMSG_NXTHDR(msg, cm))
  {
    if (cm->cmsg_level == IPPROTO_IP &&
        cm->cmsg_type == IP_TTL &&
        *(uint32_t*)CMSG_DATA(cm) == BFD_1HOPTTLVALUE)
    {
      goodTTL = true;
      break;
    }
  }

  if (!goodTTL) {
    bfdLog(LOG_INFO, "Received pkt with invalid TTL from %s:%d\n",
           inet_ntoa(sin->sin_addr), ntohs(sin->sin_port));
    return;
  }

  if (mlen < BFD_MINPKTLEN) {
    bfdLog(LOG_INFO, "Received short packet from %s:%d\n", 
           inet_ntoa(sin->sin_addr), ntohs(sin->sin_port));
    return;
  }

  cp = (bfdCpkt *)(msg->msg_iov->iov_base);

  /* Various checks from RFC 5880, section 6.8.6 */

  if (cp->version != BFD_VERSION) {
    bfdLog(LOG_INFO, "Received bad version %d from %s:%d[%x]\n",
           cp->version, inet_ntoa(sin->sin_addr),
           ntohs(sin->sin_port), ntohl(cp->myDisc));
    return;
  }

  if (cp->len < (cp->f_auth ? BFD_MINPKTLEN_AUTH : BFD_MINPKTLEN) ||
      cp->len > mlen)
  {
    bfdLog(LOG_INFO, "Invalid length %d in control pkt from %s:%d[%x]\n",
           cp->len, inet_ntoa(sin->sin_addr), ntohs(sin->sin_port),
           ntohl(cp->myDisc));
    return;
  }

  if (cp->detectMult == 0) {
    bfdLog(LOG_INFO, "Detect Mult is zero in pkt from %s:%d[%x]\n",
           inet_ntoa(sin->sin_addr), ntohs(sin->sin_port), ntohl(cp->myDisc));
    return;
  }

  if (cp->f_multipoint) {
    bfdLog(LOG_INFO, "Unsupported multipoint flag in pkt from %s:%d[%x]\n",
           inet_ntoa(sin->sin_addr), ntohs(sin->sin_port), ntohl(cp->myDisc));
    return;
  }

  if (cp->myDisc == 0) {
    bfdLog(LOG_INFO, "My discriminator is zero in pkt from %s:%d[%x]\n",
           inet_ntoa(sin->sin_addr), ntohs(sin->sin_port), ntohl(cp->myDisc));
    return;
  }

  if ((bfd = bfdGetSession(cp, sin)) == NULL) {
    bfdLog(LOG_INFO, "Can't find session for ctl pkt from %s:%d[%x]\n",
           inet_ntoa(sin->sin_addr), ntohs(sin->sin_port), ntohl(cp->myDisc));
    return;
  }

  if (cp->yourDisc == 0 &&
      !(bfd->SessionState == BFD_STATEDOWN ||
        bfd->SessionState == BFD_STATEADMINDOWN))
  {
    bfdLog(LOG_INFO, "[%x] Bad state, zero yourDiscr in pkt from %s:%d[%x]\n",
           bfd->LocalDiscr, inet_ntoa(sin->sin_addr), ntohs(sin->sin_port),
           ntohl(cp->myDisc));
    return;
  }

  if (cp->f_auth) {
    bfdLog(LOG_INFO, "[%x] Auth in use for pkt from %s:%d[%x] - UNSUPPORTED\n",
           bfd->LocalDiscr, inet_ntoa(sin->sin_addr), ntohs(sin->sin_port),
           ntohl(cp->myDisc));
    return;
  }

  bfd->RemoteDiscr = ntohl(cp->myDisc);
  bfd->RemoteSessionState = cp->state;
  bfd->RemoteDemandMode = cp->f_demand;
  bfd->RemoteMinRxInterval = ntohl(cp->requiredMinRx);

  if (bfd->pollSeqInProgress && cp->f_final) {
    bfdLog(LOG_INFO, "[%x] Poll sequence concluded to peer %s\n",
           bfd->LocalDiscr, inet_ntoa(bfd->peer));
    bfd->pollSeqInProgress = 0;
    bfd->polling = 0;
    tpStopTimer(&(bfd->xmtTimer));
    tpStopTimer(&(bfd->detectTimer));
  }

  if (cp->f_final) {
    bfd->polling = 0;
    bfd->activeDesiredMinTx = bfd->sendDesiredMinTx;
  }

  /* Calculate new transmit time */
  oldXmtTime = bfd->xmtTime;
  bfd->xmtTime = (bfd->activeDesiredMinTx > bfd->RemoteMinRxInterval) ?
                   bfd->activeDesiredMinTx : bfd->RemoteMinRxInterval;

  /* Compute detect time */
  if (!bfd->DemandModeActive) {
    uint32_t rcvDMT, selected;

    rcvDMT = ntohl(cp->desiredMinTx);
    selected = (bfd->RequiredMinRxInterval > rcvDMT) ?
                  bfd->RequiredMinRxInterval : rcvDMT;

    bfd->detectTime = cp->detectMult * selected;
  } else {
    uint32_t selected;

    selected = (bfd->activeDesiredMinTx > bfd->RemoteMinRxInterval) ?
                 bfd->activeDesiredMinTx : bfd->RemoteMinRxInterval;

    bfd->detectTime = bfd->DetectMult * selected;
  }

  /* State logic from section 6.8.6 */
  if (bfd->SessionState == BFD_STATEADMINDOWN) {
    return;
  }

  if (cp->state == BFD_STATEADMINDOWN) {
    if (bfd->SessionState != BFD_STATEDOWN) {
      bfdSessionDown(bfd, BFD_DIAG_NEIGHBORSAIDDOWN);
      sendPkt = true;
    }
  } else {
    if (bfd->SessionState == BFD_STATEDOWN) {
      if (cp->state == BFD_STATEDOWN) {
        bfd->SessionState = BFD_STATEINIT;
      } else if (cp->state == BFD_STATEINIT) {
        bfdSessionUp(bfd);
        sendPkt = true;
      }
    } else if (bfd->SessionState == BFD_STATEINIT) {
      if (cp->state == BFD_STATEINIT || cp->state == BFD_STATEUP) {
        bfdSessionUp(bfd);
        sendPkt = true;
      }
    } else { /* bfd->SessionState == BFD_STATEUP */
      if (cp->state == BFD_STATEDOWN) {
        bfdSessionDown(bfd, BFD_DIAG_NEIGHBORSAIDDOWN);
        sendPkt = true;
      }
    }
  }

  /* (Re)Calculate demand mode */
  bfd->DemandModeActive = (bfd->RemoteDemandMode &&
                           bfd->SessionState == BFD_STATEUP &&
                           bfd->RemoteSessionState == BFD_STATEUP);

  if (cp->f_poll || sendPkt) {
    bfdSendCPkt(bfd, cp->f_poll);
  } else if (oldXmtTime != bfd->xmtTime) {
    /* If new xmtTime is before next expiry */
    if (tpGetTimeRemaining(&(bfd->xmtTimer)) > (bfd->xmtTime*9)/10) {
      bfdStartXmtTimer(bfd);
    }
  }

  if (!bfd->DemandModeActive) {
    /* Restart detection timer (packet received) */
    tpStartUsTimer(&(bfd->detectTimer),
                   bfd->detectTime, bfdDetectTimeout, bfd);
  } else {
    /* Demand mode - stop detection timer */
    tpStopTimer(&(bfd->detectTimer));
  }
  return;
}

/*
 * Called on detection timeout (no ctl packets from remote system
 */
static void bfdDetectTimeout(tpTimer *tim, void *arg)
{
  bfdSession *bfd = (bfdSession *)arg;

  UNUSED(tim)

  bfdLog(LOG_NOTICE, "[%x] Detect timeout with peer %s, state %d\n",
         bfd->LocalDiscr, inet_ntoa(bfd->peer), bfd->SessionState);

  switch (bfd->SessionState) {
  case BFD_STATEUP:
  case BFD_STATEINIT:
    bfdSessionDown(bfd, BFD_DIAG_DETECTTIMEEXPIRED);
    bfdSendCPkt(bfd, 0);
    /* Session down, restart detect timer so we can clean up later */
    tpStartUsTimer(&(bfd->detectTimer), bfd->detectTime,
                   bfdDetectTimeout, bfd);
    break;
  default:
    /* Second detect time expiration, zero remote discr (section 6.5.1) */
    bfd->RemoteDiscr = 0;
    break;
  }
}

/*
 * Bring session down
 */
static void bfdSessionDown(bfdSession *bfd, uint8_t diag)
{
  uint32_t selectedMin;

  selectedMin = BFD_DOWNMINTX > bfd->DesiredMinTxInterval ?
                  BFD_DOWNMINTX : bfd->DesiredMinTxInterval;

  bfd->LocalDiag = (uint8_t)(diag & 0x1f);
  bfd->SessionState = BFD_STATEDOWN;
  bfd->sendDesiredMinTx = selectedMin;
  bfd->activeDesiredMinTx = selectedMin;
  bfd->polling = 0;
  bfd->pollSeqInProgress = 0;
  bfd->DemandModeActive = 0;

  bfdLog(LOG_NOTICE, "[%x] Session DOWN to peer %s\n", bfd->LocalDiscr,
         inet_ntoa(bfd->peer));
}

/*
 * Bring session up
 */
static void bfdSessionUp(bfdSession *bfd)
{
  bfd->SessionState = BFD_STATEUP;
  bfd->sendDesiredMinTx = bfd->DesiredMinTxInterval;
  bfd->polling = 1;

  bfdLog(LOG_NOTICE, "[%x] Session UP to peer %s\n", bfd->LocalDiscr,
         inet_ntoa(bfd->peer));
}

/*
 * Find the session corresponding to an incoming ctl packet
 */
static bfdSession *bfdGetSession(bfdCpkt *cp, struct sockaddr_in *sin)
{
  bfdSession *bfd;
  uint32_t hkey;

  if (cp->yourDisc) {
    /* Your discriminator not zero - use it to find session */
    hkey = BFD_MKHKEY(ntohl(cp->yourDisc));
    for (bfd = sessionHash[hkey]; bfd != NULL; bfd = bfd->hashNext) {
      if (bfd->LocalDiscr == ntohl(cp->yourDisc)) {
        return(bfd);
      }
    }
    bfdLog(LOG_INFO, "Can't find session for %x from %s:%d[%x]\n",
           ntohl(cp->yourDisc), inet_ntoa(sin->sin_addr),
           ntohs(sin->sin_port), ntohl(cp->myDisc));
    return(NULL);
  } else {
    /* Your discriminator zero - use peer address to find session */
    hkey = BFD_MKHKEY(sin->sin_addr.s_addr);
    for (bfd = peerHash[hkey]; bfd != NULL; bfd = bfd->peerNext) {
      if (bfd->peer.s_addr == sin->sin_addr.s_addr) {
        return(bfd);
      }
    }
    bfdLog(LOG_INFO, "Can't find session for peer %s:%d[%x]\n",
           inet_ntoa(sin->sin_addr), ntohs(sin->sin_port), cp->myDisc);
    return(NULL);
  }
}

/*
 * Send a control packet
 */
void bfdSendCPkt(bfdSession *bfd, int fbit)
{
  bfdCpkt cp;
  struct sockaddr_in sin;

  /* Set fields according to section 6.8.7 */
  cp.version = BFD_VERSION;
  cp.state = bfd->SessionState;
  cp.diag = bfd->LocalDiag;
  cp.f_demand = bfd->DemandMode ? 1 : 0;
  cp.f_poll = bfd->polling ? 1 : 0;
  cp.f_final = fbit ? 1 : 0;
  cp.f_cpi = 0;
  cp.f_auth = 0;
  cp.f_multipoint = 0;
  cp.detectMult = bfd->DetectMult;
  cp.len = BFD_MINPKTLEN;
  cp.myDisc = htonl(bfd->LocalDiscr);
  cp.yourDisc = htonl(bfd->RemoteDiscr);
  cp.desiredMinTx = htonl(bfd->sendDesiredMinTx);
  cp.requiredMinRx = htonl(bfd->RequiredMinRxInterval);
  cp.requiredMinEcho = 0;
  sin.sin_family = AF_INET;
  sin.sin_addr = bfd->peer;
  sin.sin_port = htons(bfd->peerPort);
  if (sendto(bfd->sock, &cp, BFD_MINPKTLEN, 0, (struct sockaddr *)&sin,
             sizeof(struct sockaddr_in)) < 0) {
    bfdLog(LOG_WARNING, "[%x] Error sending control pkt: %m\n",
           bfd->LocalDiscr);
  }

  /* Restart the timer for next time */
  bfdStartXmtTimer(bfd);
}

/* Buffer and msghdr for received packets */
static uint8_t msgbuf[BFD_MINPKTLEN];
static struct iovec msgiov = {
  &(msgbuf[0]),
  sizeof(msgbuf)
};
static uint8_t cmsgbuf[sizeof(struct cmsghdr) + 4];
static struct sockaddr_in msgaddr;
static struct msghdr msghdr = {
  (void *)&msgaddr,
  sizeof(msgaddr),
  &msgiov,
  1,
  (void *)&cmsgbuf,
  sizeof(cmsgbuf),
  0
};

/*
 * Create and Register socket to receive control messages
 */
static bool bfdSetupRcvSocket(bfdSession *bfd)
{
  struct sockaddr_in sin;
  int ttlval = BFD_1HOPTTLVALUE;
  int rcvttl = 1;
  int s;

  if ((s = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
    bfdLog(LOG_WARNING, "[%x] Can't get receive socket for peer %s:%d: %m\n",
           bfd->LocalDiscr, inet_ntoa(bfd->peer), bfd->peerPort);
    return false;
  }

  if (setsockopt(s, SOL_IP, IP_TTL, &ttlval, sizeof(ttlval)) < 0) {
    bfdLog(LOG_WARNING, "[%x] Can't set TTL for packets to %s:%d: %m\n",
           bfd->LocalDiscr, inet_ntoa(bfd->peer), bfd->peerPort);
    return false;
  }

  if (setsockopt(s, SOL_IP, IP_RECVTTL, &rcvttl, sizeof(rcvttl)) < 0) {
    bfdLog(LOG_WARNING,
           "[%x] Can't set receive TTL for packets from %s:%d: %m\n",
           bfd->LocalDiscr, inet_ntoa(bfd->peer), bfd->peerPort);
    return false;
  }

  sin.sin_family      = AF_INET;
  sin.sin_addr.s_addr = INADDR_ANY;
  sin.sin_port        = htons(bfd->localPort);

  if (bind(s, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
    bfdLog(LOG_WARNING,
           "[%x] Can't bind socket to port %d for peer %s:%d: %m\n",
           bfd->LocalDiscr, bfd->localPort, inet_ntoa(bfd->peer),
           bfd->peerPort);
    return false;
  }

  /* Add socket to select poll */
  tpSetSktActor(s, bfdRcvPkt, (void *)&msghdr, NULL);

  return true;
}

/*
 * Make a session state object
 */
bool bfdRegisterSession(bfdSession *bfd)
{
  struct sockaddr_in sin;
  int pcount;
  uint32_t hkey;
  static uint16_t srcPort = BFD_SRCPORTINIT;
  int ttlval = BFD_1HOPTTLVALUE;
  uint32_t selectedMin;

  bfd->LocalDiscr = (uint32_t)((uintptr_t)bfd & 0xffffffff);

  /* Make UDP socket to receive control packets */
  if (!bfdSetupRcvSocket(bfd)) {
    return false;
  }

  /* Get socket for transmitting control packets */
  if ((bfd->sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
    bfdLog(LOG_WARNING, "[%x] Can't get socket for peer %s:%d: %m\n",
           bfd->LocalDiscr, inet_ntoa(bfd->peer), bfd->peerPort);
    return false;
  }
  /* Set TTL to 255 for all transmitted packets */
  if (setsockopt(bfd->sock, SOL_IP, IP_TTL, &ttlval, sizeof(ttlval)) < 0) {
    bfdLog(LOG_WARNING, "[%x] Can't set TTL for peer %s:%d: %m\n",
           bfd->LocalDiscr, inet_ntoa(bfd->peer), bfd->peerPort);
    close(bfd->sock);
    return false;
  }
  /* Find an available source port in the proper range */
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = INADDR_ANY;
  pcount = 0;
  do {
    if ((++pcount) > (BFD_SRCPORTMAX - BFD_SRCPORTINIT)) {
      /* Searched all ports, none available */
      bfdLog(LOG_WARNING, "[%x] Can't find source port for peer %s:%d\n",
             bfd->LocalDiscr, inet_ntoa(bfd->peer), bfd->peerPort);
      close(bfd->sock);
      return false;
    }
    if (srcPort >= BFD_SRCPORTMAX) srcPort = BFD_SRCPORTINIT;
    sin.sin_port = htons(srcPort++);
  } while (bind(bfd->sock, (struct sockaddr *)&sin, sizeof(sin)) < 0);

  selectedMin = BFD_DOWNMINTX > bfd->DesiredMinTxInterval ?
                  BFD_DOWNMINTX : bfd->DesiredMinTxInterval;

  /* Initialize the session */
  bfd->SessionState = BFD_STATEDOWN;
  bfd->sendDesiredMinTx = selectedMin;
  bfd->activeDesiredMinTx = selectedMin;
  bfd->xmtTime = selectedMin;
  bfd->listNext = sessionList;
  bfd->LocalDiag = 0;
  sessionList = bfd;
  hkey = BFD_MKHKEY(bfd->LocalDiscr);
  bfd->hashNext = sessionHash[hkey];
  sessionHash[hkey] = bfd;
  hkey = BFD_MKHKEY(bfd->peer.s_addr);
  bfd->peerNext = peerHash[hkey];
  peerHash[hkey] = bfd;
  /* Start transmitting control packets */
  bfdXmtTimeout(&(bfd->xmtTimer), bfd);
  bfdLog(LOG_NOTICE, "[%x] Created new session with peer %s:%d\n",
         bfd->LocalDiscr, inet_ntoa(bfd->peer), bfd->peerPort);
  return true;
}

/*
 * Called for each transmission interval timeout
 */
static void bfdXmtTimeout(tpTimer *tim, void *arg)
{
  bfdSession *bfd = (bfdSession *)arg;

  UNUSED(tim)

  /* Send the scheduled control packet */
  bfdSendCPkt(bfd, 0);
}

/*
 * Start the transmission timer with appropriate jitter
 */
void bfdStartXmtTimer(bfdSession *bfd)
{
  uint32_t jitter;
  uint32_t maxpercent;

  /*
   * From section 6.8.7: trasmit interval should be randomly jittered between
   * 75% and 100% of nominal value, unless DetectMult is 1, then should be
   * between 75% and 90%.
   */
  maxpercent = (bfd->DetectMult == 1) ? 16 : 26;
  jitter = (bfd->xmtTime*(75 + ((uint32_t)random() % maxpercent)))/100;
  tpStartUsTimer(&(bfd->xmtTimer), jitter, bfdXmtTimeout, bfd);
}

/*
 * Destroy a session (never gets called in current code)
 */
void bfdRmSession(bfdSession *bfd)
{
  uint32_t hkey;

  hkey = BFD_MKHKEY(bfd->LocalDiscr);
  if (bfdRmFromList(&(sessionHash[hkey]), bfd) < 0) {
    bfdLog(LOG_ERR, "Can't find session %x in session hash\n", bfd->LocalDiscr);
  }
  hkey = BFD_MKHKEY(bfd->peer.s_addr);
  if (bfdRmFromList(&(peerHash[hkey]), bfd) < 0) {
    bfdLog(LOG_ERR, "Can't find session %x in peer hash\n", bfd->LocalDiscr);
  }
  if (bfdRmFromList(&sessionList, bfd) < 0) {
    bfdLog(LOG_ERR, "Can't find session %x in session list\n", bfd->LocalDiscr);
  }
  tpStopTimer(&(bfd->xmtTimer));
  tpStopTimer(&(bfd->detectTimer));
}

/*
 * Remove a session from a list
 */
int bfdRmFromList(bfdSession **list, bfdSession *bfd)
{
  bfdSession *prev = NULL;
  bfdSession *tmp;

  for (tmp = *list; tmp; tmp = tmp->hashNext) {
    if (tmp->LocalDiscr == bfd->LocalDiscr) {
      if (prev) {
        prev->hashNext = bfd->hashNext;
      } else {
        *list = bfd->hashNext;
      }
      return(0);
    }
    prev = tmp;
  }
  return(-1);
}

/*
 * Called on receipt of SIGUSR1.  Start poll sequence on all demand
 * mode sessions.
 */
void bfdStartPollSequence(int sig)
{
  bfdSession *bfd;

  UNUSED(sig)

  for (bfd = sessionList; bfd != NULL; bfd = bfd->listNext) {
    if (bfd->DemandMode && (!bfd->pollSeqInProgress)) {
      bfd->pollSeqInProgress = 1;
      bfd->polling = 1;
      bfdXmtTimeout(&(bfd->xmtTimer), bfd);
      tpStartUsTimer(&(bfd->detectTimer),
                     bfd->detectTime,
                     bfdDetectTimeout,
                     bfd);
      bfdLog(LOG_INFO, "[%x] Poll sequence started to peer %s:%d, timer %d\n",
             bfd->LocalDiscr, inet_ntoa(bfd->peer), bfd->peerPort,
             bfd->detectTime);
    }
  }
}

/*
 * Called on receipt of SIGUSR2.  Toggle ADMINDOWN status on all
 * sessions.
 */
void bfdToggleAdminDown(int sig)
{
  bfdSession *bfd;

  UNUSED(sig)

  for (bfd = sessionList; bfd != NULL; bfd = bfd->listNext) {
    if (bfd->SessionState == BFD_STATEADMINDOWN) {
      /* Session is already ADMINDOWN, enable it */
      bfd->SessionState = BFD_STATEDOWN;
      bfdXmtTimeout(&(bfd->xmtTimer), bfd);
      bfdLog(LOG_NOTICE, "[%x] Session to peer %s:%d enabled\n",
             bfd->LocalDiscr, inet_ntoa(bfd->peer), bfd->peerPort);
    } else {
      uint32_t selectedMin;

      selectedMin = BFD_DOWNMINTX > bfd->DesiredMinTxInterval ?
                      BFD_DOWNMINTX : bfd->DesiredMinTxInterval;

      /* Disable session */
      bfd->SessionState = BFD_STATEADMINDOWN;
      bfd->polling = 0;
      bfd->LocalDiag = BFD_DIAG_ADMINDOWN;
      bfd->DemandModeActive = 0;
      bfd->pollSeqInProgress = 0;
      bfd->RemoteDiscr = 0;
      bfd->sendDesiredMinTx = selectedMin;
      bfd->activeDesiredMinTx = selectedMin;
      tpStopTimer(&(bfd->xmtTimer));
      tpStopTimer(&(bfd->detectTimer));
      bfdLog(LOG_NOTICE, "[%x] Session to peer %s:%d disabled\n",
             bfd->LocalDiscr, inet_ntoa(bfd->peer), bfd->peerPort);
    }
  }
}
