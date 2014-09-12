/*
 * This file implements the Bi-drectional Forwarding Detection (BFD) Protocol
 * with IPv4 single-hop encapsulation, as described in draft-katz-ward-bfd-01.txt
 * and draft-katz-ward-bfd-v4v6-1hop-00.txt.
 *
 * It implements all of the protocol features except for echo packets.  It
 * does not implement much in the way of user interface - just command line
 * options.  In its current state this is really only useful for interoperability
 * testing.
 *
 * Author:   Tom Phelan
 *           Sonus Networks
 *           tphelan@sonusnet.com
 *
 * Copyright (c) 2003 Sonus Networks, Inc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <time.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdbool.h>
#include "bfd.h"
#include "tp-timers.h"

#define UNUSED(x) { if(x){} }

int bfdDebug = BFD_DEFDEBUG;

/*
 * Session defaults
 */
uint8_t defDemandModeDesired = BFD_DEFDEMANDMODEDESIRED;
uint8_t defDetectMult = BFD_DEFDETECTMULT;
uint32_t defDesiredMinTx = BFD_DEFDESIREDMINTX;
uint32_t defRequiredMinRx = BFD_DEFREQUIREDMINRX;

/* Buffer and msghdr for received packets */
uint8_t msgbuf[BFD_CPKTLEN];
struct iovec msgiov = {
  &(msgbuf[0]),
  sizeof(msgbuf)
};
uint8_t cmsgbuf[sizeof(struct cmsghdr) + 4];
struct sockaddr_in msgaddr;
struct msghdr msghdr = {
  (void *)&msgaddr,
  sizeof(msgaddr),
  &msgiov,
  1,
  (void *)&cmsgbuf,
  sizeof(cmsgbuf),
  0
};

bfdSession *sessionList;                  /* List of active sessions */
bfdSession *sessionHash[BFD_HASHSIZE];    /* Find session from discriminator */
bfdSession *peerHash[BFD_HASHSIZE];       /* Find session from peer address */

int ttlval = 255;
int rcvttl = 1;

/*
 * Command line usage info
 */
void bfdUsage(void)
{
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "\tbfdd [-b] -c connectaddr[:port] [-d] [-l localport] [-m mult] [-r tout] [-t tout]\n");
  fprintf(stderr, "Where:\n");
  fprintf(stderr, "\t-b: toggle debug mode (default %s)\n", BFD_DEFDEBUG ? "on" : "off");
  fprintf(stderr, "\t-c: create session with 'connectaddr' (required option)\n");
  fprintf(stderr, "\t    optionally override dest port (default %d)\n", BFD_DEFDESTPORT);
  fprintf(stderr, "\t-l: listen on 'localport' (default %d)\n", BFD_DEFDESTPORT);
  fprintf(stderr, "\t-d: toggle demand mode desired (default %s)\n",
          BFD_DEFDEMANDMODEDESIRED ? "on" : "off");
  fprintf(stderr, "\t-m mult: detect multiplier (default %d)\n", BFD_DEFDETECTMULT);
  fprintf(stderr, "\t-r tout: required min rx (default %d)\n", BFD_DEFREQUIREDMINRX);
  fprintf(stderr, "\t-t tout: desired min tx (default %d)\n", BFD_DEFDESIREDMINTX);
  fprintf(stderr, "Signals:\n");
  fprintf(stderr, "\tUSR1: start poll sequence on all demand mode sessions\n");
  fprintf(stderr, "\tUSR2: toggle admin down on all sessions\n");
}

/*
 * All received packets come through here.
 */
void bfdRcvPkt(int s, void *arg)
{
  struct msghdr *msg = (struct msghdr *)arg;
  int mlen;
  struct sockaddr_in *sin;
  bfdCpkt *cp;
  struct cmsghdr *cm;
  bfdSession *bfd;
  uint32_t oldXmtTime;
  bool goodTTL = false;

  /* Get packet */
  if ((mlen = recvmsg(s, msg, 0)) < 0) {
    bfdLog(LOG_ERR, "Error receiving from BFD socket: %m\n");
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
        *(uint32_t*)CMSG_DATA(cm) == BFD_TTLVALUE)
    {
      goodTTL = true;
      break;
    }
  }
  if (!goodTTL) {
    bfdLog(LOG_NOTICE, "Received pkt with invalid TTL from %s\n",
           inet_ntoa(sin->sin_addr));
    return;
  }
  /* Various checks from section 6.5.6 */
  if (mlen < BFD_CPKTLEN) {
    bfdLog(LOG_NOTICE, "Received short packet from %s\n", 
           inet_ntoa(sin->sin_addr));
    return;
  }
  cp = (bfdCpkt *)(msg->msg_iov->iov_base);
  if (BFD_GETVER(cp->diag) != BFD_VERSION) {
    bfdLog(LOG_NOTICE, "Received bad version %d from %s\n", BFD_GETVER(cp->diag),
           inet_ntoa(sin->sin_addr));
    return;
  }
  if ((cp->len < BFD_CPKTLEN) || (cp->len > mlen)) {
    bfdLog(LOG_NOTICE, "Invalid length %d in control pkt from %s\n", cp->len,
           inet_ntoa(sin->sin_addr));
    return;
  }
  if (cp->detectMult == 0) {
    bfdLog(LOG_NOTICE, "Detect Mult is zero in pkt from %s\n",
           inet_ntoa(sin->sin_addr));
    return;
  }
  if (cp->myDisc == 0) {
    bfdLog(LOG_NOTICE, "My discriminator is zero in pkt from %s\n",
           inet_ntoa(sin->sin_addr));
    return;
  }
  if ((cp->yourDisc == 0) && (cp->flags & BFD_IHEARYOU)) {
    bfdLog(LOG_NOTICE, "Zero Your Discriminator and non-zero I Hear You in pkt from %s\n",
           inet_ntoa(sin->sin_addr));
    return;
  }
  if ((bfd = bfdGetSession(cp, sin)) == NULL) {
    bfdLog(LOG_NOTICE, "Can't find session for ctl pkt from %s\n",
           inet_ntoa(sin->sin_addr));
    return;
  }
  if (bfd->remoteDiscr == 0) {
    bfd->remoteDiscr = ntohl(cp->myDisc);
  }
  if (bfd->remoteDiscr != ntohl(cp->myDisc)) {
    bfdLog(LOG_NOTICE, "My Descriptor mismatch in pkt from %s\n",
           inet_ntoa(sin->sin_addr));
    return;
  }
  if (bfd->pollSeqInProgress) {
    bfdLog(LOG_NOTICE, "Poll sequence concluded for session 0x%x to peer %s\n",
           bfd->localDiscr, inet_ntoa(bfd->peer));
    bfd->pollSeqInProgress = 0;
    bfd->polling = 0;
    tpStopTimer(&(bfd->xmtTimer));
    tpStopTimer(&(bfd->detectTimer));
  }
  if (!bfd->demandMode) {
    if ((cp->flags & BFD_FBIT)) {
      bfd->polling = 0;
      bfd->activeDesiredMinTx = bfd->desiredMinTx;
    }
    /* Compute detect time */
    bfd->detectTime = cp->detectMult*((bfd->requiredMinRx > ntohl(cp->desiredMinTx)) ?
      bfd->requiredMinRx : ntohl(cp->desiredMinTx));
  }
  /* State switch from section 6.5.6 */
  switch (bfd->sessionState) {
  case (BFD_STATEDOWN):
    bfd->remoteHeard = 1;
    if ((cp->flags & BFD_IHEARYOU)) {
      bfdSessionUp(bfd);
    } else {
      bfd->sessionState = BFD_STATEINIT;
    }
    break;
  case (BFD_STATEADMINDOWN):
    return;
  case (BFD_STATEINIT):
    if ((cp->flags & BFD_IHEARYOU)) {
      bfdSessionUp(bfd);
      break;
    } else {
      return;
    }
  case (BFD_STATEUP):
    if (!(cp->flags & BFD_IHEARYOU)) {
      bfdLog(LOG_NOTICE, "Neigbor down on session 0x%x with peer %s\n",
             bfd->localDiscr, inet_ntoa(bfd->peer));
      bfdSessionDown(bfd, BFD_DIAGNEIGHDOWN);
    }
    break;
  case (BFD_STATEFAILING):
    if (!(cp->flags & BFD_IHEARYOU)) {
      bfd->sessionState = BFD_STATEDOWN;
    }
    break;
  }
  /* Calculate new transmit time */
  oldXmtTime = bfd->xmtTime;
  bfd->xmtTime = (bfd->activeDesiredMinTx > ntohl(cp->requiredMinRx)) ?
    bfd->activeDesiredMinTx : ntohl(cp->requiredMinRx);
  /* (Re)Calculate demand mode */
  bfd->demandMode = ((cp->flags & BFD_DEMANDBIT) && bfd->demandModeDesired &&
                     (bfd->sessionState == BFD_STATEUP));
  if ((cp->flags & BFD_PBIT)) {
    bfdSendCPkt(bfd, 1);
  }
  /* If transmit time has changed, and too much time until next xmt, restart */
  if (oldXmtTime != bfd->xmtTime) {
    if (tpGetTimeRemaining(&(bfd->xmtTimer)) > (bfd->xmtTime*9)/10) {
      bfdStartXmtTimer(bfd);
    }
  }
  if (!bfd->demandMode) {
    /* Restart detection timer (packet received) */
    tpStartUsTimer(&(bfd->detectTimer), bfd->detectTime, bfdDetectTimeout, bfd);
  } else {
    /* Demand mode - stop detection timer */
    tpStopTimer(&(bfd->detectTimer));
  }
  return;
}

/*
 * Called on detection timeout (no ctl packets from remote system
 */
void bfdDetectTimeout(tpTimer *tim, void *arg)
{
  bfdSession *bfd = (bfdSession *)arg;

  UNUSED(tim)

  bfdLog(LOG_NOTICE, "Detect timeout on session 0x%x with peer %s, in state %d\n",
         bfd->localDiscr, inet_ntoa(bfd->peer), bfd->sessionState);
  switch (bfd->sessionState) {
  case BFD_STATEUP:
  case BFD_STATEINIT:
    bfdSessionDown(bfd, BFD_DIAGDETECTTIME);
    /* Session down, restart detect timer so we can clean up later */
    tpStartUsTimer(&(bfd->detectTimer), bfd->detectTime,
                   bfdDetectTimeout, bfd);
    break;
  default:
    /* Second detect time expiration, zero remote discr (section 6.5.1) */
    bfd->remoteDiscr = 0;
    break;
  }
}

/*
 * Bring session down
 */
void bfdSessionDown(bfdSession *bfd, uint8_t diag)
{
  bfd->localDiag = diag;
  bfd->remoteHeard = 0;
  bfd->sessionState = BFD_STATEFAILING;
  bfd->desiredMinTx = BFD_DOWNMINTX;
  bfd->activeDesiredMinTx = BFD_DOWNMINTX;
  bfd->polling = 0;
  bfd->pollSeqInProgress = 0;
  bfd->demandMode = 0;
  if (!bfd->upDownSent) {
    bfd->upDownSent = 1;
    bfdSendCPkt(bfd, 0);
  }
  bfdLog(LOG_WARNING, "Session 0x%x down to peer %s\n", bfd->localDiscr,
         inet_ntoa(bfd->peer));
}

/*
 * Bring session up
 */
void bfdSessionUp(bfdSession *bfd)
{
  bfd->sessionState = BFD_STATEUP;
  bfd->desiredMinTx = bfd->upMinTx;
  bfd->polling = 1;
  if (!bfd->upDownSent) {
    bfd->upDownSent = 1;
    /* Nothing sent since last xmt time, send immediate indication */
    bfdSendCPkt(bfd, 0);
  }
  bfdLog(LOG_NOTICE, "Session 0x%x up to peer %s\n", bfd->localDiscr,
         inet_ntoa(bfd->peer));
}

/*
 * Find the session corresponding to an incoming ctl packet
 */
bfdSession *bfdGetSession(bfdCpkt *cp, struct sockaddr_in *sin)
{
  bfdSession *bfd;
  uint32_t hkey;

  if (cp->yourDisc) {
    /* Your discriminator not zero - use it to find session */
    hkey = BFD_MKHKEY(ntohl(cp->yourDisc));
    for (bfd = sessionHash[hkey]; bfd != NULL; bfd = bfd->hashNext) {
      if (bfd->localDiscr == ntohl(cp->yourDisc)) {
        return(bfd);
      }
    }
    bfdLog(LOG_NOTICE, "Can't find session for yourDisc 0x%x from %s\n",
           ntohl(cp->yourDisc), inet_ntoa(sin->sin_addr));
    return(NULL);
  } else {
    /* Your discriminator zero - use peer address to find session */
    hkey = BFD_MKHKEY(sin->sin_addr.s_addr);
    for (bfd = peerHash[hkey]; bfd != NULL; bfd = bfd->peerNext) {
      if (bfd->peer.s_addr == sin->sin_addr.s_addr) {
        return(bfd);
      }
    }
    bfdLog(LOG_NOTICE, "Can't find session for peer %s\n",
           inet_ntoa(sin->sin_addr));
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

  /* Set fields according to section 6.5.7 */
  cp.diag = bfd->localDiag;
  cp.flags = 0;
  BFD_SETIHEARYOU(cp.flags, bfd->remoteHeard);
  BFD_SETDEMANDBIT(cp.flags, bfd->demandModeDesired);
  BFD_SETPBIT(cp.flags, bfd->polling);
  BFD_SETFBIT(cp.flags, fbit);
  cp.detectMult = bfd->detectMult;
  cp.len = BFD_CPKTLEN;
  cp.myDisc = htonl(bfd->localDiscr);
  cp.yourDisc = htonl(bfd->remoteDiscr);
  cp.desiredMinTx = htonl(bfd->desiredMinTx);
  cp.requiredMinRx = htonl(bfd->requiredMinRx);
  cp.requiredMinEcho = 0;
  sin.sin_family = AF_INET;
  sin.sin_addr = bfd->peer;
  sin.sin_port = htons(bfd->peerPort);
  if (sendto(bfd->sock, &cp, BFD_CPKTLEN, 0, (struct sockaddr *)&sin,
             sizeof(struct sockaddr_in)) < 0) {
    bfdLog(LOG_ERR, "Error sending control pkt: %m\n");
  }
}

/*
 * Make a session state object
 */
bfdSession *bfdMkSession(struct in_addr peer,
                         uint16_t peerPort,
                         uint32_t remoteDisc)
{
  bfdSession *bfd;
  struct sockaddr_in sin;
  int pcount;
  uint32_t hkey;
  static int srcPort = BFD_SRCPORTINIT;

  /* Get memory */
  if ((bfd = (bfdSession*)malloc(sizeof(bfdSession))) == NULL) {
    bfdLog(LOG_NOTICE, "Can't malloc memory for new session: %m\n");
    return(NULL);
  }
  memset(bfd, 0, sizeof(bfdSession));
  /*
   * Get socket for transmitting control packets.  Note that if we could use
   * the destination port (3784) for the source port we wouldn't need a
   * socket per session.
   */
  if ((bfd->sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
    bfdLog(LOG_NOTICE, "Can't get socket for new session: %m\n");
    free(bfd);
    return(NULL);
  }
  /* Set TTL to 255 for all transmitted packets */
  if (setsockopt(bfd->sock, SOL_IP, IP_TTL, &ttlval, sizeof(ttlval)) < 0) {
    bfdLog(LOG_ERR, "Can't set TTL for new session: %m\n");
    close(bfd->sock);
    free(bfd);
    return(NULL);
  }
  /* Find an available source port in the proper range */
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = INADDR_ANY;
  pcount = 0;
  do {
    if ((++pcount) > (BFD_SRCPORTMAX - BFD_SRCPORTINIT)) {
      /* Searched all ports, none available */
      bfdLog(LOG_NOTICE, "Can't find source port for new session\n");
      close(bfd->sock);
      free(bfd);
      return(NULL);
    }
    if (srcPort >= BFD_SRCPORTMAX) srcPort = BFD_SRCPORTINIT;
    sin.sin_port = htons(srcPort++);
  } while (bind(bfd->sock, (struct sockaddr *)&sin, sizeof(sin)) < 0);
  /* Initialize the session */
  bfd->sessionState = BFD_STATEFAILING;
  bfd->demandModeDesired = defDemandModeDesired;
  bfd->detectMult = defDetectMult;
  bfd->localDiscr = (uint32_t)bfd;
  bfd->remoteDiscr = remoteDisc;
  bfd->desiredMinTx = BFD_DOWNMINTX;
  bfd->activeDesiredMinTx = BFD_DOWNMINTX;
  bfd->upMinTx = defDesiredMinTx;
  bfd->requiredMinRx = defRequiredMinRx;
  bfd->peer = peer;
  bfd->peerPort = peerPort;
  bfd->xmtTime = BFD_DOWNMINTX;
  bfd->listNext = sessionList;
  sessionList = bfd;
  hkey = BFD_MKHKEY(bfd->localDiscr);
  bfd->hashNext = sessionHash[hkey];
  sessionHash[hkey] = bfd;
  hkey = BFD_MKHKEY(peer.s_addr);
  bfd->peerNext = peerHash[hkey];
  peerHash[hkey] = bfd;
  /* Start transmitting control packets */
  bfdXmtTimeout(&(bfd->xmtTimer), bfd);
  bfdLog(LOG_NOTICE, "Created new session 0x%x with peer %s\n",
         bfd->localDiscr, inet_ntoa(bfd->peer));
  return(bfd);
}

/*
 * Called for each transmission interval timeout
 */
void bfdXmtTimeout(tpTimer *tim, void *arg)
{
  bfdSession *bfd = (bfdSession *)arg;

  UNUSED(tim)

  /* Allow intra-interval control packets again */
  bfd->upDownSent = 0;
  /* Send the scheduled control packet */
  bfdSendCPkt(bfd, 0);
  /* Restart the timer for next time */
  bfdStartXmtTimer(bfd);
}

/*
 * Start the transmission timer with appropriate jitter
 */
void bfdStartXmtTimer(bfdSession *bfd)
{
  uint32_t jitter;
  int maxpercent;

  /*
   * From section 6.5.2: trasmit interval should be randomly jittered between
   * 75% and 100% of nominal value, unless detectMult is 1, then should be
   * between 75% and 90%.
   */
  maxpercent = (bfd->detectMult == 1) ? 16 : 26;
  jitter = (bfd->xmtTime*(75 + (random() % maxpercent)))/100;
  tpStartUsTimer(&(bfd->xmtTimer), jitter, bfdXmtTimeout, bfd);
}

/*
 * Destroy a session (never gets called in current code)
 */
void bfdRmSession(bfdSession *bfd)
{
  uint32_t hkey;

  hkey = BFD_MKHKEY(bfd->localDiscr);
  if (bfdRmFromList(&(sessionHash[hkey]), bfd) < 0) {
    bfdLog(LOG_ERR, "Can't find session 0x%x in session hash\n", bfd->localDiscr);
  }
  hkey = BFD_MKHKEY(bfd->peer.s_addr);
  if (bfdRmFromList(&(peerHash[hkey]), bfd) < 0) {
    bfdLog(LOG_ERR, "Can't find session 0x%x in peer hash\n", bfd->localDiscr);
  }
  if (bfdRmFromList(&sessionList, bfd) < 0) {
    bfdLog(LOG_ERR, "Can't find session 0x%x in session list\n", bfd->localDiscr);
  }
  tpStopTimer(&(bfd->xmtTimer));
  tpStopTimer(&(bfd->detectTimer));
  free(bfd);
}

/*
 * Remove a session from a list
 */
int bfdRmFromList(bfdSession **list, bfdSession *bfd)
{
  bfdSession *prev = NULL;
  bfdSession *tmp;

  for (tmp = *list; tmp; tmp = tmp->hashNext) {
    if (tmp->localDiscr == bfd->localDiscr) {
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
    if (bfd->demandMode && (!bfd->pollSeqInProgress)) {
      bfd->pollSeqInProgress = 1;
      bfd->polling = 1;
      bfdXmtTimeout(&(bfd->xmtTimer), bfd);
      tpStartUsTimer(&(bfd->detectTimer), bfd->detectTime, bfdDetectTimeout, bfd);
      bfdLog(LOG_NOTICE, "Poll sequence started for session 0x%x to peer %s, timer %d\n",
             bfd->localDiscr, inet_ntoa(bfd->peer), bfd->detectTime);
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
    if (bfd->sessionState == BFD_STATEADMINDOWN) {
      /* Session is already ADMINDOWN, enable it */
      bfd->sessionState = BFD_STATEFAILING;
      bfdXmtTimeout(&(bfd->xmtTimer), bfd);
      bfdLog(LOG_NOTICE, "Session 0x%x to peer %s enabled\n", bfd->localDiscr,
             inet_ntoa(bfd->peer));
    } else {
      /* Disable session */
      bfd->sessionState = BFD_STATEADMINDOWN;
      bfd->remoteHeard = 0;
      bfd->polling = 0;
      bfd->localDiag = BFD_DIAGADMINDOWN;
      bfd->demandMode = 0;
      bfd->pollSeqInProgress = 0;
      bfd->upDownSent = 0;
      bfd->remoteDiscr = 0;
      bfd->desiredMinTx = BFD_DOWNMINTX;
      bfd->activeDesiredMinTx = BFD_DOWNMINTX;
      tpStopTimer(&(bfd->xmtTimer));
      tpStopTimer(&(bfd->detectTimer));
      bfdLog(LOG_NOTICE, "Session 0x%x to peer %s disabled\n", bfd->localDiscr,
             inet_ntoa(bfd->peer));
    }
  }
}

/*
 * Main entry point of process
 */
int main(int argc, char **argv)
{
  int c, s;
  char *connectaddr = NULL;
  char *cptr;
  struct hostent *hp;
  struct in_addr peeraddr;
  uint16_t peerPort = BFD_DEFDESTPORT;
  struct sockaddr_in sin;
  uint16_t localport = BFD_DEFDESTPORT;

  /* Init random() */
  srandom(time(NULL));
  /* Get command line options */
  while ((c = getopt(argc, argv, "bc:dhl:m:r:t:")) != -1) {
    switch (c) {
    case 'b':
      bfdDebug = !bfdDebug;
      break;
    case 'c':
      connectaddr = optarg;
      if ((cptr = strchr(connectaddr, ':')) != NULL) {
        uint32_t tmp;

        *cptr = '\0';
        cptr++;
        sscanf(cptr, "%u", &tmp);
        peerPort = tmp & 0xffff;
      }
      break;
    case 'd':
      defDemandModeDesired = !defDemandModeDesired;
      break;
    case 'h':
      bfdUsage();
      exit(0);
    case 'l':
      localport = atoi(optarg);
      break;
    case 'm':
      defDetectMult = atoi(optarg);
      break;
    case 'r':
      defRequiredMinRx = atoi(optarg);
      break;
    case 't':
      defDesiredMinTx = atoi(optarg);
      break;
    default:
      bfdUsage();
      exit(1);
    }
  }
  /* Must have specified peer address */
  if (connectaddr == NULL) {
    bfdUsage();
    exit(1);
  }
  openlog(BFD_LOGID, LOG_PID | (bfdDebug ? LOG_PERROR : 0), LOG_DAEMON);
  if (!bfdDebug) {
    if (daemon(0, 0) < 0) {
      bfdLog(LOG_ERR, "Can't daemonize: %m\n");
      exit(1);
    }
  }
  bfdLog(LOG_NOTICE,
         "BFD: demandModeDesired %s, detectMult %d, desiredMinTx %d, requiredMinRx %d\n",
         (defDemandModeDesired ? "on" : "off"), defDetectMult, defDesiredMinTx,
         defRequiredMinRx);

  /* Init timers package */
  tpInitTimers();

  /* Set signal handlers */
  tpSetSignalActor(bfdStartPollSequence, SIGUSR1);
  tpSetSignalActor(bfdToggleAdminDown, SIGUSR2);

  /* Make UDP socket to receive control packets */
  if ((s = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
    bfdLog(LOG_ERR, "Can't get receive socket: %m\n");
    exit(1);
  }
  if (setsockopt(s, SOL_IP, IP_TTL, &ttlval, sizeof(ttlval)) < 0) {
    bfdLog(LOG_ERR, "Can't set TTL for outgoing packets: %m\n");
    exit(1);
  }
  if (setsockopt(s, SOL_IP, IP_RECVTTL, &rcvttl, sizeof(rcvttl)) < 0) {
    bfdLog(LOG_ERR, "Can't set receive TTL for incoming packets: %m\n");
    exit(1);
  }
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = INADDR_ANY;
  sin.sin_port = htons(localport);
  if (bind(s, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
    bfdLog(LOG_ERR, "Can't bind socket to port %d: %m\n", localport);
    exit(1);
  }
  /* Add socket to select poll */
  tpSetSktActor(s, bfdRcvPkt, (void *)&msghdr, NULL);

  /* Get peer address */
  if ((hp = gethostbyname(connectaddr)) == NULL) {
    bfdLog(LOG_ERR, "Can't resolve %s: %s\n", connectaddr, hstrerror(h_errno));
    exit(1);
  }
  if (hp->h_addrtype != AF_INET) {
    bfdLog(LOG_ERR, "Resolved address type not AF_INET\n");
    exit(1);
  }
  memcpy(&peeraddr, hp->h_addr, sizeof(peeraddr));

  /* Make the initial session */
  bfdLog(LOG_INFO, "Creating initial session with %s (%s)\n", connectaddr,
         inet_ntoa(peeraddr));
  if (bfdMkSession(peeraddr, peerPort, 0) == NULL) {
    bfdLog(LOG_ERR, "Can't creating initial session: %m\n");
    exit(1);
  }

  /* Wait for events */
  tpDoEventLoop();
  /* Should never return */
  exit(1);
}
