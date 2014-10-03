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
#include "bfdExtensions.h"
#include "tp-timers.h"

/*
 * Session defaults
 */
static uint8_t  defDemandModeDesired = BFDDFLT_DEMANDMODE;
static uint8_t  defDetectMult        = BFDDFLT_DETECTMULT;
static uint32_t defDesiredMinTx      = BFDDFLT_DESIREDMINTX;
static uint32_t defRequiredMinRx     = BFDDFLT_REQUIREDMINRX;

/*
 * Command line usage info
 */
static void bfdUsage(void)
{
  int idx;

  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "\tbfdd -c connectaddr[:port] [-d] [-l localport] [-m mult] [-r tout] [-t tout] \n"
                  "\t     [-v] [-x extension]\n");
  fprintf(stderr, "Where:\n");
  fprintf(stderr, "\t-c: create session with 'connectaddr' (required option)\n");
  fprintf(stderr, "\t    optionally override dest port (default %d)\n", BFDDFLT_UDPPORT);
  fprintf(stderr, "\t-l: listen on 'localport' (default %d)\n", BFDDFLT_UDPPORT);
  fprintf(stderr, "\t-d: toggle demand mode desired (default %s)\n",
          BFDDFLT_DEMANDMODE? "on" : "off");
  fprintf(stderr, "\t-m mult: detect multiplier (default %d)\n", BFDDFLT_DETECTMULT);
  fprintf(stderr, "\t-r tout: required min rx (default %d)\n", BFDDFLT_REQUIREDMINRX);
  fprintf(stderr, "\t-t tout: desired min tx (default %d)\n", BFDDFLT_DESIREDMINTX);
  fprintf(stderr, "\t-v: increase level of debug output (can be repeated)\n");
  fprintf(stderr, "\t-x extension: enable a named extension (can be repeated)\n");
  for (idx=0; idx < BFD_EXT_MAX; idx++) {
    const char* name;
    const char* desc;

    bfdExtDescribe(idx, &name, &desc);
    fprintf(stderr, "\t\t%s\t%s\n", name, desc);
  }
  fprintf(stderr, "\n");
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
  struct in_addr localaddr = { .s_addr = INADDR_ANY };
  uint16_t peerPort = BFDDFLT_UDPPORT;
  uint16_t localPort = BFDDFLT_UDPPORT;

  bfdSession bfd;

  /* Init random() */
  srandom((unsigned int)time(NULL));

  bfdLogInit();

  /* Get command line options */
  while ((c = getopt(argc, argv, "c:dhl:m:r:t:vx:")) != -1) {
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
      if (sscanf(optarg, "%" SCNu16, &localPort) != 1) {
         fprintf(stderr, "Arg 'localport' must be an integer\n\n");
         bfdUsage();
         exit(1);
      }
      break;
    case 'm':
      if (sscanf(optarg, "%" SCNu8, &defDetectMult) != 1) {
         fprintf(stderr, "Arg 'mult' must be an integer\n\n");
         bfdUsage();
         exit(1);
      }
      break;
    case 'r':
      if (sscanf(optarg, "%" SCNu32, &defRequiredMinRx) != 1) {
         fprintf(stderr, "Arg 'tout' must be an integer\n\n");
         bfdUsage();
         exit(1);
      }
      break;
    case 't':
      if (sscanf(optarg, "%" SCNu32, &defDesiredMinTx) != 1) {
         fprintf(stderr, "Arg 'tout' must be an integer\n\n");
         bfdUsage();
         exit(1);
      }
      break;
    case 'v':
      bfdLogMore();
      break;
    case 'x':
      if (!bfdExtEnable(optarg)) {
        fprintf(stderr, "Invalid extension: %s\n", optarg);
        bfdUsage();
        exit(1);
      }
      break;
    default:
      bfdUsage();
      exit(1);
    }
  }

  if (!bfdExtCheck(BFD_EXT_SPECIFYPORTS)) {
    if (peerPort != BFDDFLT_UDPPORT) {
      fprintf(stderr, "Invalid remote port: %d\n", peerPort);
      fprintf(stderr, "Did you forget to enable the SpecifyPorts extension?\n");
      bfdUsage();
      exit(1);
    }

    if (localPort != BFDDFLT_UDPPORT) {
      fprintf(stderr, "Invalid local port: %d\n", localPort);
      fprintf(stderr, "Did you forget to enable the SpecifyPorts extension?\n");
      bfdUsage();
      exit(1);
    }
  }

  /* Must have specified peer address */
  if (connectaddr == NULL) {
    fprintf(stderr, "No peer address (connectaddr) specified\n");
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

  memset(&bfd, 0, sizeof(bfdSession));

  bfd.DemandMode            = defDemandModeDesired;
  bfd.DetectMult            = defDetectMult;
  bfd.DesiredMinTxInterval  = defDesiredMinTx;
  bfd.RequiredMinRxInterval = defRequiredMinRx;
  bfd.PeerAddr              = peeraddr;
  bfd.LocalAddr             = localaddr;
  bfd.PeerPort              = peerPort;
  bfd.LocalPort             = localPort;

  bfdSessionSetStrings(&bfd);

  /* Make the initial session */
  bfdLog(LOG_INFO, "Creating initial session with %s (%s)\n", connectaddr,
         bfd.SnIdStr);

  if (!bfdCreateSession(&bfd)) {
    bfdLog(LOG_ERR, "Can't creating initial session: %m\n");
    exit(1);
  }

  /* Wait for events */
  tpDoEventLoop();

  /* Should never return */
  exit(1);
}
