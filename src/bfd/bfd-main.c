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
#include <stdbool.h>
#include "bfd.h"
#include "bfdLog.h"
#include "tp-timers.h"

/*
 * Session defaults
 */
static bool     defDemandModeDesired = BFDDFLT_DEMANDMODE;
static uint8_t  defDetectMult        = BFDDFLT_DETECTMULT;
static uint32_t defDesiredMinTx      = BFDDFLT_DESIREDMINTX;
static uint32_t defRequiredMinRx     = BFDDFLT_REQUIREDMINRX;

/*
 * Command line usage info
 */
static void bfdUsage(void)
{
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "\tbfd -p <PeerAddress> [-d] [-m mult] [-r tout] [-t tout] \n"
                  "\t     [-v] [-x <extension>[=<value>]]\n");
  fprintf(stderr, "Where:\n");
  fprintf(stderr, "\t-p: create session with 'PeerAddress' (required option)\n");
  fprintf(stderr, "\t-d: toggle demand mode desired (default %s)\n",
          BFDDFLT_DEMANDMODE? "on" : "off");
  fprintf(stderr, "\t-m mult: detect multiplier (default %d)\n", BFDDFLT_DETECTMULT);
  fprintf(stderr, "\t-r tout: required min rx (default %d)\n", BFDDFLT_REQUIREDMINRX);
  fprintf(stderr, "\t-t tout: desired min tx (default %d)\n", BFDDFLT_DESIREDMINTX);
  fprintf(stderr, "\t-v: increase level of debug output (can be repeated)\n");
  fprintf(stderr, "\t-x <extension>[=<value>]: configure a specific extension\n\t   (no spaces allowed)\n");
  fprintf(stderr, "\t\tPeerPort=<peer UDP port #> (default %d)\n", BFDDFLT_UDPPORT);
  fprintf(stderr, "\t\tLocalPort=<local UDP port #>\n");
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
  struct hostent *hp;
  struct in_addr PeerAddr;
  struct in_addr localaddr = { .s_addr = INADDR_ANY };
  uint16_t PeerPort = BFDDFLT_UDPPORT;
  uint16_t LocalPort = BFDDFLT_UDPPORT;

  bfdSession bfd;

  /* Init random() */
  srandom((unsigned int)time(NULL));

  bfdLogInit();

  /* Get command line options */
  while ((c = getopt(argc, argv, "dhm:p:r:t:vx:")) != -1) {
    switch (c) {
    case 'd':
      defDemandModeDesired = !defDemandModeDesired;
      break;
    case 'h':
      bfdUsage();
      exit(0);
    case 'm':
      if (sscanf(optarg, "%" SCNu8, &defDetectMult) != 1) {
         fprintf(stderr, "Arg 'mult' must be an integer\n\n");
         bfdUsage();
         exit(1);
      }
      break;
    case 'p':
      connectaddr = optarg;
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
      {
        size_t l;
        long int val;

        l = strlen(optarg);

        if (l > 9 && strncmp("PeerPort=", optarg, 9) == 0) {
          val = strtol(optarg + 9, NULL, 10);
          if (val <= 0 || val > 0xffff) {
            fprintf(stderr, "PeerPort must be a 16-bit unsigned integer\n\n");
            bfdUsage();
            exit(1);
          }

          PeerPort = (uint16_t)val;
        } else if (l > 10 && strncmp("LocalPort=", optarg, 10) == 0) {
          val = strtol(optarg + 10, NULL, 10);

          if (val <= 0 || val > 0xffff) {
            fprintf(stderr, "LocalPort must be a 16-bit unsigned integer\n\n");
            bfdUsage();
            exit(1);
          }

          LocalPort = (uint16_t)val;
        } else {
          fprintf(stderr, "Unknown extension: %s\n\n", optarg);
          bfdUsage();
          exit(1);
        }
      }
      break;
    default:
      bfdUsage();
      exit(1);
    }
  }

  /* Must have specified peer address */
  if (connectaddr == NULL) {
    fprintf(stderr, "No peer address specified (-p option is required)\n");
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

  memcpy(&PeerAddr, hp->h_addr, sizeof(PeerAddr));

  memset(&bfd, 0, sizeof(bfdSession));

  bfd.DemandMode            = defDemandModeDesired;
  bfd.DetectMult            = defDetectMult;
  bfd.DesiredMinTxInterval  = defDesiredMinTx;
  bfd.RequiredMinRxInterval = defRequiredMinRx;
  bfd.PeerAddr              = PeerAddr;
  bfd.LocalAddr             = localaddr;
  bfd.PeerPort              = PeerPort;
  bfd.LocalPort             = LocalPort;

  bfdSessionSetStrings(&bfd);

  /* Make the initial session */
  bfdLog(LOG_INFO, "Creating initial session with %s (%s)\n", connectaddr,
         bfd.SnIdStr);

  if (!bfdCreateSession(&bfd)) {
    bfdLog(LOG_ERR, "Can't create initial session\n");
    exit(1);
  }

  /* Wait for events */
  tpDoEventLoop();

  /* Should never return */
  exit(1);
}
