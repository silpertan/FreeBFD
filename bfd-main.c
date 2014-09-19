#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include "bfd.h"
#include "bfdLog.h"

/*
 * Session defaults
 */
static uint8_t  defDemandModeDesired = BFD_DEFDEMANDMODEDESIRED;
static uint8_t  defDetectMult        = BFD_DEFDETECTMULT;
static uint32_t defDesiredMinTx      = BFD_DEFDESIREDMINTX;
static uint32_t defRequiredMinRx     = BFD_DEFREQUIREDMINRX;

/*
 * Command line usage info
 */
static void bfdUsage(void)
{
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "\tbfdd -c connectaddr[:port] [-d] [-l localport] [-m mult] [-r tout] [-t tout] [-v]\n");
  fprintf(stderr, "Where:\n");
  fprintf(stderr, "\t-c: create session with 'connectaddr' (required option)\n");
  fprintf(stderr, "\t    optionally override dest port (default %d)\n", BFD_DEFDESTPORT);
  fprintf(stderr, "\t-l: listen on 'localport' (default %d)\n", BFD_DEFDESTPORT);
  fprintf(stderr, "\t-d: toggle demand mode desired (default %s)\n",
          BFD_DEFDEMANDMODEDESIRED ? "on" : "off");
  fprintf(stderr, "\t-m mult: detect multiplier (default %d)\n", BFD_DEFDETECTMULT);
  fprintf(stderr, "\t-r tout: required min rx (default %d)\n", BFD_DEFREQUIREDMINRX);
  fprintf(stderr, "\t-t tout: desired min tx (default %d)\n", BFD_DEFDESIREDMINTX);
  fprintf(stderr, "\t-v: increase level of debug output (can be repeated)\n");
  fprintf(stderr, "Signals:\n");
  fprintf(stderr, "\tUSR1: start poll sequence on all demand mode sessions\n");
  fprintf(stderr, "\tUSR2: toggle admin down on all sessions\n");
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
  srandom((unsigned int)time(NULL));

  bfdLogInit();

  /* Get command line options */
  while ((c = getopt(argc, argv, "c:dhl:m:r:t:v")) != -1) {
    switch (c) {
    case 'c':
      connectaddr = optarg;
      if ((cptr = strchr(connectaddr, ':')) != NULL) {
        uint32_t tmp;

        *cptr = '\0';
        cptr++;
        sscanf(cptr, "%" SCNu32, &tmp);
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
      if (sscanf(optarg, "%" SCNu16, &localport) != 1) {
         fprintf(stderr, "Arg 'localport' must be an integer\n\n");
         bfdUsage();
         exit(0);
      }
      break;
    case 'm':
      if (sscanf(optarg, "%" SCNu8, &defDetectMult) != 1) {
         fprintf(stderr, "Arg 'mult' must be an integer\n\n");
         bfdUsage();
         exit(0);
      }
      break;
    case 'r':
      if (sscanf(optarg, "%" SCNu32, &defRequiredMinRx) != 1) {
         fprintf(stderr, "Arg 'tout' must be an integer\n\n");
         bfdUsage();
         exit(0);
      }
      break;
    case 't':
      if (sscanf(optarg, "%" SCNu32, &defDesiredMinTx) != 1) {
         fprintf(stderr, "Arg 'tout' must be an integer\n\n");
         bfdUsage();
         exit(0);
      }
      break;
    case 'v':
      bfdLogMore();
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

  bfdLog(LOG_NOTICE,
         "BFD: demandModeDesired %s, detectMult %d, desiredMinTx %d, requiredMinRx %d\n",
         (defDemandModeDesired ? "on" : "off"), defDetectMult, defDesiredMinTx,
         defRequiredMinRx);

  /* Init timers package */
  tpInitTimers();

  /* Set signal handlers */
  tpSetSignalActor(bfdStartPollSequence, SIGUSR1);
  tpSetSignalActor(bfdToggleAdminDown, SIGUSR2);

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

  bfd->DemandMode            = (uint8_t)(defDemandModeDesired & 0x1);
  bfd->DetectMult            = defDetectMult;
  bfd->DesiredMinTxInterval  = defDesiredMinTx;
  bfd->RequiredMinRxInterval = defRequiredMinRx;
  bfd->peer                  = peeraddr;
  bfd->peerPort              = peerPort;
  bfd->localPort             = localport;

  if (!bfdRegisterSession(bfd)) {
    bfdLog(LOG_ERR, "Can't creating initial session: %m\n");
    exit(1);
  }

  /* Wait for events */
  tpDoEventLoop();

  /* Should never return */
  exit(1);
}
