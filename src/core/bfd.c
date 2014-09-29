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
#include "bfdInt.h"
#include "tp-timers.h"
#include "bfdLog.h"
#include "bfdExtensions.h"

#define UNUSED(x) { if(x){} }

static bfdSessionInt *sessionList;                  /* List of active sessions */
static bfdSessionInt *sessionHash[BFD_HASHSIZE];    /* Find session from discriminator */
static bfdSessionInt *peerHash[BFD_HASHSIZE];       /* Find session from peer address */

static bfdSessionInt *bfdGetSession(bfdCpkt *cp, struct sockaddr_in *sin);
static bfdSessionInt *bfdMatchSession(bfdSession *_bfd);
static void bfdXmtTimeout(tpTimer *tim, void *arg);
static void bfdSessionDown(bfdSessionInt *bfd, uint8_t diag);
static void bfdSessionUp(bfdSessionInt *bfd);
static void bfdDetectTimeout(tpTimer *tim, void *arg);
static bool bfdSetupRcvSocket(bfdSessionInt *bfd);

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
  bfdSessionInt *bfd;
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
      !(bfd->SessionState == BFDSTATE_DOWN ||
        bfd->SessionState == BFDSTATE_ADMINDOWN))
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

  if (bfd->PollSeqInProgress && cp->f_final) {
    bfdLog(LOG_INFO, "[%x] Poll sequence concluded to peer %s\n",
           bfd->LocalDiscr, inet_ntoa(bfd->Sn.PeerAddr));
    bfd->PollSeqInProgress = 0;
    bfd->Polling = 0;
    tpStopTimer(&(bfd->XmtTimer));
    tpStopTimer(&(bfd->DetectTimer));
  }

  if (cp->f_final) {
    bfd->Polling = 0;
    bfd->ActiveDesiredMinTx = bfd->SendDesiredMinTx;
  }

  /* Calculate new transmit time */
  oldXmtTime = bfd->XmtTime;
  bfd->XmtTime = (bfd->ActiveDesiredMinTx > bfd->RemoteMinRxInterval) ?
                   bfd->ActiveDesiredMinTx : bfd->RemoteMinRxInterval;

  /* Compute detect time */
  if (!bfd->DemandModeActive) {
    uint32_t rcvDMT, selected;

    rcvDMT = ntohl(cp->desiredMinTx);
    selected = (bfd->Sn.RequiredMinRxInterval > rcvDMT) ?
                  bfd->Sn.RequiredMinRxInterval : rcvDMT;

    bfd->DetectTime = cp->detectMult * selected;
  } else {
    uint32_t selected;

    selected = (bfd->ActiveDesiredMinTx > bfd->RemoteMinRxInterval) ?
                 bfd->ActiveDesiredMinTx : bfd->RemoteMinRxInterval;

    bfd->DetectTime = bfd->Sn.DetectMult * selected;
  }

  /* State logic from section 6.8.6 */
  if (bfd->SessionState == BFDSTATE_ADMINDOWN) {
    return;
  }

  if (cp->state == BFDSTATE_ADMINDOWN) {
    if (bfd->SessionState != BFDSTATE_DOWN) {
      bfdSessionDown(bfd, BFDDIAG_NEIGHBORSAIDDOWN);
      sendPkt = true;
    }
  } else {
    if (bfd->SessionState == BFDSTATE_DOWN) {
      if (cp->state == BFDSTATE_DOWN) {
        bfd->SessionState = BFDSTATE_INIT;
      } else if (cp->state == BFDSTATE_INIT) {
        bfdSessionUp(bfd);
        sendPkt = true;
      }
    } else if (bfd->SessionState == BFDSTATE_INIT) {
      if (cp->state == BFDSTATE_INIT || cp->state == BFDSTATE_UP) {
        bfdSessionUp(bfd);
        sendPkt = true;
      }
    } else { /* bfd->SessionState == BFDSTATE_UP */
      if (cp->state == BFDSTATE_DOWN) {
        bfdSessionDown(bfd, BFDDIAG_NEIGHBORSAIDDOWN);
        sendPkt = true;
      }
    }
  }

  /* (Re)Calculate demand mode */
  bfd->DemandModeActive = (bfd->RemoteDemandMode &&
                           bfd->SessionState == BFDSTATE_UP &&
                           bfd->RemoteSessionState == BFDSTATE_UP);

  if (cp->f_poll || sendPkt) {
    bfdSendCPkt(bfd, cp->f_poll);
  } else if (oldXmtTime != bfd->XmtTime) {
    /* If new xmtTime is before next expiry */
    if (tpGetTimeRemaining(&(bfd->XmtTimer)) > (bfd->XmtTime*9)/10) {
      bfdStartXmtTimer(bfd);
    }
  }

  if (!bfd->DemandModeActive) {
    /* Restart detection timer (packet received) */
    tpStartUsTimer(&(bfd->DetectTimer),
                   bfd->DetectTime, bfdDetectTimeout, bfd);
  } else {
    /* Demand mode - stop detection timer */
    tpStopTimer(&(bfd->DetectTimer));
  }
  return;
}

/*
 * Called on detection timeout (no ctl packets from remote system
 */
static void bfdDetectTimeout(tpTimer *tim, void *arg)
{
  bfdSessionInt *bfd = (bfdSessionInt *)arg;

  UNUSED(tim)

  bfdLog(LOG_NOTICE, "[%x] Detect timeout with peer %s, state %d\n",
         bfd->LocalDiscr, inet_ntoa(bfd->Sn.PeerAddr), bfd->SessionState);

  switch (bfd->SessionState) {
  case BFDSTATE_UP:
  case BFDSTATE_INIT:
    bfdSessionDown(bfd, BFDDIAG_DETECTTIMEEXPIRED);
    bfdSendCPkt(bfd, 0);
    /* Session down, restart detect timer so we can clean up later */
    tpStartUsTimer(&(bfd->DetectTimer), bfd->DetectTime,
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
static void bfdSessionDown(bfdSessionInt *bfd, uint8_t diag)
{
  uint32_t selectedMin;

  selectedMin = BFD_DOWNMINTX > bfd->Sn.DesiredMinTxInterval ?
                  BFD_DOWNMINTX : bfd->Sn.DesiredMinTxInterval;

  bfd->LocalDiag = (uint8_t)(diag & 0x1f);
  bfd->SessionState = BFDSTATE_DOWN;
  bfd->SendDesiredMinTx = selectedMin;
  bfd->ActiveDesiredMinTx = selectedMin;
  bfd->Polling = 0;
  bfd->PollSeqInProgress = 0;
  bfd->DemandModeActive = 0;

  bfdLog(LOG_NOTICE, "[%x] Session DOWN to peer %s\n", bfd->LocalDiscr,
         inet_ntoa(bfd->Sn.PeerAddr));
}

/*
 * Bring session up
 */
static void bfdSessionUp(bfdSessionInt *bfd)
{
  bfd->SessionState = BFDSTATE_UP;
  bfd->SendDesiredMinTx = bfd->Sn.DesiredMinTxInterval;
  bfd->Polling = 1;

  bfdLog(LOG_NOTICE, "[%x] Session UP to peer %s\n", bfd->LocalDiscr,
         inet_ntoa(bfd->Sn.PeerAddr));
}

/*
 * Find the session corresponding to an incoming ctl packet
 */
static bfdSessionInt *bfdGetSession(bfdCpkt *cp, struct sockaddr_in *sin)
{
  bfdSessionInt *bfd;
  uint32_t hkey;

  if (cp->yourDisc) {
    /* Your discriminator not zero - use it to find session */
    hkey = BFD_MKHKEY(ntohl(cp->yourDisc));
    for (bfd = sessionHash[hkey]; bfd != NULL; bfd = bfd->HashNext) {
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
    for (bfd = peerHash[hkey]; bfd != NULL; bfd = bfd->PeerNext) {
      if (bfd->Sn.PeerAddr.s_addr == sin->sin_addr.s_addr) {
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
void bfdSendCPkt(bfdSessionInt *bfd, int fbit)
{
  bfdCpkt cp;
  struct sockaddr_in sin;

  /* Set fields according to section 6.8.7 */
  cp.version = BFD_VERSION;
  cp.state = bfd->SessionState;
  cp.diag = bfd->LocalDiag;
  cp.f_demand = bfd->Sn.DemandMode ? 1 : 0;
  cp.f_poll = bfd->Polling;
  cp.f_final = fbit ? 1 : 0;
  cp.f_cpi = 0;
  cp.f_auth = 0;
  cp.f_multipoint = 0;
  cp.detectMult = bfd->Sn.DetectMult;
  cp.len = BFD_MINPKTLEN;
  cp.myDisc = htonl(bfd->LocalDiscr);
  cp.yourDisc = htonl(bfd->RemoteDiscr);
  cp.desiredMinTx = htonl(bfd->SendDesiredMinTx);
  cp.requiredMinRx = htonl(bfd->Sn.RequiredMinRxInterval);
  cp.requiredMinEcho = 0;
  sin.sin_family = AF_INET;
  sin.sin_addr = bfd->Sn.PeerAddr;
  sin.sin_port = htons(bfd->Sn.PeerPort);
  if (sendto(bfd->Sock, &cp, BFD_MINPKTLEN, 0, (struct sockaddr *)&sin,
             sizeof(struct sockaddr_in)) < 0) {
    bfdLog(LOG_WARNING, "[%x] Error sending control pkt: %m\n",
           bfd->LocalDiscr);
  }

  /* Restart the timer for next time */
  bfdStartXmtTimer(bfd);
}

/* Searches for an exact match using the Session Discriminator
 * values in the bfdSession.
 */
static bfdSessionInt *bfdMatchSession(bfdSession *_bfd)
{
  uint32_t hkey;
  bfdSessionInt *bfd;

  hkey = BFD_MKHKEY(_bfd->PeerAddr.s_addr);
  for (bfd = peerHash[hkey]; bfd != NULL; bfd = bfd->PeerNext) {
    if (bfd->Sn.PeerAddr.s_addr == _bfd->PeerAddr.s_addr &&
        bfd->Sn.PeerPort == _bfd->PeerPort &&
        bfd->Sn.LocalPort == _bfd->LocalPort)
    {
      return(bfd);
    }
  }

  return NULL;
}

bfdSubHndl bfdSubscribe(bfdSession *_bfd, bfdSubCB cb, void *arg)
{
  bfdSessionInt *bfd;
  bfdNotifier *notify;

  if (cb == NULL) {
    bfdLog(LOG_WARNING, "Subscribing with NULL callback not supported\n");
    return NULL;
  }

  notify = calloc(1, sizeof(bfdNotifier));
  if (notify == NULL) {
    bfdLog(LOG_ERR, "Unable to allocate memory for notifier: %m\n");
    return NULL;
  }

  notify->cb = cb;
  notify->cbArg = arg;

  /* determine if the session exists or needs to be created */
  if ((bfd = bfdMatchSession(_bfd)) == NULL) {
    if (!bfdCreateSession(_bfd)) { return NULL; }
  } else {
    bfdLog(LOG_NOTICE, "[%x] Adding notifier to session with peer %s:%d\n",
           bfd->LocalDiscr, inet_ntoa(bfd->Sn.PeerAddr), bfd->Sn.PeerPort);
  }

  /* add the notification object to the session */
  notify->sn = bfd;
  notify->next = bfd->notify;
  bfd->notify = notify;

  /* Thoughts about reference counts.  Sessions are created in the following
   * ways:
   * - one session per process (e.g. bfd -c <ip-addr>)
   * - by configuration file to bfdd
   * - via subscription on the control socket
   * - [future] on-demand sessions
   * All but the on-demand case should be created via bfdSubscribe().
   */
  bfd->RefCnt++;

  /* convey the current state of the session so that the subscriber can
   * set itself up properly
   */
  cb(bfd->SessionState, arg);

  return (void*)notify;
}

void bfdUnsubscribe(bfdSubHndl hndl)
{
  bfdNotifier *notify = (bfdNotifier*)hndl;
  bfdSessionInt *bfd;

  if (notify == NULL) { return; }

  bfd = notify->sn;

  /* remove the notification object from the session */
  if (bfd->notify == notify) {
    bfd->notify = notify->next;
  } else {
    bfdNotifier *cur = bfd->notify->next;
    bfdNotifier *prev = bfd->notify;

    while (cur) {
      if (cur == notify) {
        prev->next = cur->next;
        break;
      }

      prev = cur;
      cur = cur->next;
    }

    if (cur == NULL) {
      bfdLog(LOG_WARNING,
             "Attempt to unsubscribe non-existent notifier [%x]", hndl);
      return;
    }
  }

  free(notify);

  /* if there are no more listeners for the session, delete it */
  if (bfd->RefCnt <= 0) {
    bfdRmSession(bfd);
  }
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
static bool bfdSetupRcvSocket(bfdSessionInt *bfd)
{
  struct sockaddr_in sin;
  int ttlval = BFD_1HOPTTLVALUE;
  int rcvttl = 1;
  int s;

  if ((s = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
    bfdLog(LOG_WARNING, "[%x] Can't get receive socket for peer %s:%d: %m\n",
           bfd->LocalDiscr, inet_ntoa(bfd->Sn.PeerAddr), bfd->Sn.PeerPort);
    return false;
  }

  if (setsockopt(s, SOL_IP, IP_TTL, &ttlval, sizeof(ttlval)) < 0) {
    bfdLog(LOG_WARNING, "[%x] Can't set TTL for packets to %s:%d: %m\n",
           bfd->LocalDiscr, inet_ntoa(bfd->Sn.PeerAddr), bfd->Sn.PeerPort);
    return false;
  }

  if (setsockopt(s, SOL_IP, IP_RECVTTL, &rcvttl, sizeof(rcvttl)) < 0) {
    bfdLog(LOG_WARNING,
           "[%x] Can't set receive TTL for packets from %s:%d: %m\n",
           bfd->LocalDiscr, inet_ntoa(bfd->Sn.PeerAddr), bfd->Sn.PeerPort);
    return false;
  }

  sin.sin_family      = AF_INET;
  sin.sin_addr.s_addr = INADDR_ANY;
  sin.sin_port        = htons(bfd->Sn.LocalPort);

  if (bind(s, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
    bfdLog(LOG_WARNING,
           "[%x] Can't bind socket to port %d for peer %s:%d: %m\n",
           bfd->LocalDiscr, bfd->Sn.LocalPort, inet_ntoa(bfd->Sn.PeerAddr),
           bfd->Sn.PeerPort);
    return false;
  }

  /* Add socket to select poll */
  tpSetSktActor(s, bfdRcvPkt, (void *)&msghdr, NULL);

  return true;
}

/*
 * Make a session state object
 */
bool bfdCreateSession(bfdSession *_bfd)
{
  struct sockaddr_in sin;
  int pcount;
  uint32_t hkey;
  static uint16_t srcPort = BFD_SRCPORTINIT;
  int ttlval = BFD_1HOPTTLVALUE;
  uint32_t selectedMin;
  bfdSessionInt *bfd;

  if (!bfdExtCheck(BFD_EXT_SPECIFYPORTS)) {
    if (_bfd->PeerPort != BFDDFLT_DESTPORT) {
      bfdLog(LOG_WARNING, "Invalid remote port: %d\n", _bfd->PeerPort);
      bfdLog(LOG_WARNING,
             "Did you forget to enable the SpecifyPorts extension?\n");
      return false;
    }

    if (_bfd->LocalPort != BFDDFLT_DESTPORT) {
      bfdLog(LOG_WARNING, "Invalid local port: %d\n", _bfd->LocalPort);
      bfdLog(LOG_WARNING,
             "Did you forget to enable the SpecifyPorts extension?\n");
      return false;
    }
  }

  bfd = calloc(1, sizeof(bfdSessionInt));
  if (bfd == NULL) {
    bfdLog(LOG_ERR, "Unable to allocate BFD session: %m\n");
    return false;
  }

  memcpy(&bfd->Sn, _bfd, sizeof(bfdSession));

  bfd->LocalDiscr = (uint32_t)((uintptr_t)bfd & 0xffffffff);

  /* Make UDP socket to receive control packets */
  if (!bfdSetupRcvSocket(bfd)) {
    return false;
  }

  /* Get socket for transmitting control packets */
  if ((bfd->Sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
    bfdLog(LOG_WARNING, "[%x] Can't get socket for peer %s:%d: %m\n",
           bfd->LocalDiscr, inet_ntoa(bfd->Sn.PeerAddr), bfd->Sn.PeerPort);
    return false;
  }
  /* Set TTL to 255 for all transmitted packets */
  if (setsockopt(bfd->Sock, SOL_IP, IP_TTL, &ttlval, sizeof(ttlval)) < 0) {
    bfdLog(LOG_WARNING, "[%x] Can't set TTL for peer %s:%d: %m\n",
           bfd->LocalDiscr, inet_ntoa(bfd->Sn.PeerAddr), bfd->Sn.PeerPort);
    close(bfd->Sock);
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
             bfd->LocalDiscr, inet_ntoa(bfd->Sn.PeerAddr), bfd->Sn.PeerPort);
      close(bfd->Sock);
      return false;
    }
    if (srcPort >= BFD_SRCPORTMAX) srcPort = BFD_SRCPORTINIT;
    sin.sin_port = htons(srcPort++);
  } while (bind(bfd->Sock, (struct sockaddr *)&sin, sizeof(sin)) < 0);

  selectedMin = BFD_DOWNMINTX > bfd->Sn.DesiredMinTxInterval ?
                  BFD_DOWNMINTX : bfd->Sn.DesiredMinTxInterval;

  /* Initialize the session */
  bfd->SessionState = BFDSTATE_DOWN;
  bfd->SendDesiredMinTx = selectedMin;
  bfd->ActiveDesiredMinTx = selectedMin;
  bfd->XmtTime = selectedMin;
  bfd->ListNext = sessionList;
  bfd->LocalDiag = 0;
  sessionList = bfd;
  hkey = BFD_MKHKEY(bfd->LocalDiscr);
  bfd->HashNext = sessionHash[hkey];
  sessionHash[hkey] = bfd;
  hkey = BFD_MKHKEY(bfd->Sn.PeerAddr.s_addr);
  bfd->PeerNext = peerHash[hkey];
  peerHash[hkey] = bfd;
  /* Start transmitting control packets */
  bfdXmtTimeout(&(bfd->XmtTimer), bfd);
  bfdLog(LOG_NOTICE, "[%x] Created new session with peer %s:%d\n",
         bfd->LocalDiscr, inet_ntoa(bfd->Sn.PeerAddr), bfd->Sn.PeerPort);
  return true;
}

/*
 * Called for each transmission interval timeout
 */
static void bfdXmtTimeout(tpTimer *tim, void *arg)
{
  bfdSessionInt *bfd = (bfdSessionInt *)arg;

  UNUSED(tim)

  /* Send the scheduled control packet */
  bfdSendCPkt(bfd, 0);
}

/*
 * Start the transmission timer with appropriate jitter
 */
void bfdStartXmtTimer(bfdSessionInt *bfd)
{
  uint32_t jitter;
  uint32_t maxpercent;

  /*
   * From section 6.8.7: trasmit interval should be randomly jittered between
   * 75% and 100% of nominal value, unless DetectMult is 1, then should be
   * between 75% and 90%.
   */
  maxpercent = (bfd->Sn.DetectMult == 1) ? 16 : 26;
  jitter = (bfd->XmtTime*(75 + ((uint32_t)random() % maxpercent)))/100;
  tpStartUsTimer(&(bfd->XmtTimer), jitter, bfdXmtTimeout, bfd);
}

bool bfdDeleteSession(bfdSession *_bfd)
{
  bfdSessionInt *bfd;

  if ((bfd = bfdMatchSession(_bfd)) == NULL) {
    bfdLog(LOG_WARNING, "Attempt to delete unkonwn session\n");
    return false;
  }

  bfdRmSession(bfd);
  free(bfd);

  return true;
}

/*
 * Destroy a session
 */
void bfdRmSession(bfdSessionInt *bfd)
{
  uint32_t hkey;

  /* TODO: Need to close out the session */

  hkey = BFD_MKHKEY(bfd->LocalDiscr);
  if (bfdRmFromList(&(sessionHash[hkey]), bfd) < 0) {
    bfdLog(LOG_ERR, "Can't find session %x in session hash\n", bfd->LocalDiscr);
  }
  hkey = BFD_MKHKEY(bfd->Sn.PeerAddr.s_addr);
  if (bfdRmFromList(&(peerHash[hkey]), bfd) < 0) {
    bfdLog(LOG_ERR, "Can't find session %x in peer hash\n", bfd->LocalDiscr);
  }
  if (bfdRmFromList(&sessionList, bfd) < 0) {
    bfdLog(LOG_ERR, "Can't find session %x in session list\n", bfd->LocalDiscr);
  }
  tpStopTimer(&(bfd->XmtTimer));
  tpStopTimer(&(bfd->DetectTimer));
}

/*
 * Remove a session from a list
 */
int bfdRmFromList(bfdSessionInt **list, bfdSessionInt *bfd)
{
  bfdSessionInt *prev = NULL;
  bfdSessionInt *tmp;

  for (tmp = *list; tmp; tmp = tmp->HashNext) {
    if (tmp->LocalDiscr == bfd->LocalDiscr) {
      if (prev) {
        prev->HashNext = bfd->HashNext;
      } else {
        *list = bfd->HashNext;
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
  bfdSessionInt *bfd;

  UNUSED(sig)

  for (bfd = sessionList; bfd != NULL; bfd = bfd->ListNext) {
    if (bfd->Sn.DemandMode && (!bfd->PollSeqInProgress)) {
      bfd->PollSeqInProgress = 1;
      bfd->Polling = 1;
      bfdXmtTimeout(&(bfd->XmtTimer), bfd);
      tpStartUsTimer(&(bfd->DetectTimer),
                     bfd->DetectTime,
                     bfdDetectTimeout,
                     bfd);
      bfdLog(LOG_INFO, "[%x] Poll sequence started to peer %s:%d, timer %d\n",
             bfd->LocalDiscr, inet_ntoa(bfd->Sn.PeerAddr), bfd->Sn.PeerPort,
             bfd->DetectTime);
    }
  }
}

/*
 * Called on receipt of SIGUSR2.  Toggle ADMINDOWN status on all
 * sessions.
 */
void bfdToggleAdminDown(int sig)
{
  bfdSessionInt *bfd;

  UNUSED(sig)

  for (bfd = sessionList; bfd != NULL; bfd = bfd->ListNext) {
    if (bfd->SessionState == BFDSTATE_ADMINDOWN) {
      /* Session is already ADMINDOWN, enable it */
      bfd->SessionState = BFDSTATE_DOWN;
      bfdXmtTimeout(&(bfd->XmtTimer), bfd);
      bfdLog(LOG_NOTICE, "[%x] Session to peer %s:%d enabled\n",
             bfd->LocalDiscr, inet_ntoa(bfd->Sn.PeerAddr), bfd->Sn.PeerPort);
    } else {
      uint32_t selectedMin;

      selectedMin = BFD_DOWNMINTX > bfd->Sn.DesiredMinTxInterval ?
                      BFD_DOWNMINTX : bfd->Sn.DesiredMinTxInterval;

      /* Disable session */
      bfd->SessionState = BFDSTATE_ADMINDOWN;
      bfd->Polling = 0;
      bfd->LocalDiag = BFDDIAG_ADMINDOWN;
      bfd->DemandModeActive = 0;
      bfd->PollSeqInProgress = 0;
      bfd->RemoteDiscr = 0;
      bfd->SendDesiredMinTx = selectedMin;
      bfd->ActiveDesiredMinTx = selectedMin;
      tpStopTimer(&(bfd->XmtTimer));
      tpStopTimer(&(bfd->DetectTimer));
      bfdLog(LOG_NOTICE, "[%x] Session to peer %s:%d disabled\n",
             bfd->LocalDiscr, inet_ntoa(bfd->Sn.PeerAddr), bfd->Sn.PeerPort);
    }
  }
}
