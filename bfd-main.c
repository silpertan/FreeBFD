#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "bfd.h"

/*
 * Session defaults
 */
static uint8_t  defDemandModeDesired = BFD_DEFDEMANDMODEDESIRED;
static uint8_t  defDetectMult        = BFD_DEFDETECTMULT;
static uint32_t defDesiredMinTx      = BFD_DEFDESIREDMINTX;
static uint32_t defRequiredMinRx     = BFD_DEFREQUIREDMINRX;

/* Buffer and msghdr for received packets */
static uint8_t msgbuf[BFD_CPKTLEN];
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
 * Command line usage info
 */
static void bfdUsage(void)
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
 * Create and Register socket to receive control messages
 */
static void setupRcvSocket(uint16_t localport)
{
  struct sockaddr_in sin;
  int ttlval = BFD_1HOPTTLVALUE;
  int rcvttl = 1;
  int s;

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

  sin.sin_family      = AF_INET;
  sin.sin_addr.s_addr = INADDR_ANY;
  sin.sin_port        = htons(localport);

  if (bind(s, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
    bfdLog(LOG_ERR, "Can't bind socket to port %d: %m\n", localport);
    exit(1);
  }

  /* Add socket to select poll */
  tpSetSktActor(s, bfdRcvPkt, (void *)&msghdr, NULL);
}

/*
 * Main entry point of process
 */
int main(int argc, char **argv)
{
  int c;
  char *connectaddr = NULL;
  char *cptr;
  struct hostent *hp;
  struct in_addr peeraddr;
  uint16_t peerPort = BFD_DEFDESTPORT;
  uint16_t localport = BFD_DEFDESTPORT;

  bfdSession *bfd;

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
  setupRcvSocket(localport);

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

  /* Get memory */
  if ((bfd = (bfdSession*)malloc(sizeof(bfdSession))) == NULL) {
    bfdLog(LOG_NOTICE, "Can't malloc memory for new session: %m\n");
    exit(1);
  }

  memset(bfd, 0, sizeof(bfdSession));

  bfd->demandModeDesired = defDemandModeDesired;
  bfd->detectMult        = defDetectMult;
  bfd->upMinTx           = defDesiredMinTx;
  bfd->requiredMinRx     = defRequiredMinRx;
  bfd->peer              = peeraddr;
  bfd->peerPort          = peerPort;
  // bfd->remoteDiscr = 0;

  if (!bfdInitSession(bfd)) {
    bfdLog(LOG_ERR, "Can't creating initial session: %m\n");
    exit(1);
  }

  /* Wait for events */
  tpDoEventLoop();

  /* Should never return */
  exit(1);
}
