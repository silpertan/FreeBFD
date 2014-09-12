#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <libconfig.h>
#include "bfd.h"

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
static void bfddUsage(void)
{
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "\tbfdd -c config-file\n");
  fprintf(stderr, "Where:\n");
  fprintf(stderr, "\t-c: load 'config-file' for startup configuration\n");
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
  char *configFile = NULL;

  config_t cfg;
  config_setting_t *sns;

  /* Get command line options */
  while ((c = getopt(argc, argv, "c:")) != -1) {
    switch (c) {
    case 'c':
      configFile = optarg;
      break;
    default:
      bfddUsage();
      exit(1);
    }
  }

  /* Must have specified peer address */
  if (configFile == NULL) {
    bfddUsage();
    exit(1);
  }

  openlog(BFD_LOGID, LOG_PID | (bfdDebug ? LOG_PERROR : 0), LOG_DAEMON);

  if (daemon(1, 0) != 0) {
    bfdLog(LOG_ERR, "Unable to daemonize!");
    exit(1);
  }

  /* Init random() */
  srandom((unsigned int)time(NULL));

  /* Init timers package */
  tpInitTimers();

  /* Set signal handlers */
  tpSetSignalActor(bfdStartPollSequence, SIGUSR1);
  tpSetSignalActor(bfdToggleAdminDown, SIGUSR2);

  config_init(&cfg);

  /* Read the file */
  if(!config_read_file(&cfg, configFile)) {            
    bfdLog(LOG_ERR, "Error loading config file [%s]: %s:%d - %s\n",
           configFile,
           config_error_file(&cfg),
           config_error_line(&cfg),
           config_error_text(&cfg));
    config_destroy(&cfg);
    exit(1);
  }

  if ((sns = config_lookup(&cfg, "Sessions")) != NULL) {
    int32_t cnt = config_setting_length(sns);
    uint32_t i;

    for (i=0; i<cnt; i++) {
      struct hostent *hp;
      struct in_addr peeraddr;
      const char *connectaddr = NULL;
      int32_t peerPort;
      int32_t localport;
      int32_t demandMode;
      int32_t detectMult;
      int32_t reqMinRx;
      int32_t desMinTx;
      bfdSession *bfd;

      config_setting_t *sn = config_setting_get_elem(sns, i);

      if (!config_setting_lookup_string(sn, "PeerAddress", &connectaddr)) {
        bfdLog(LOG_ERR, "Session %d missing PeerAddress - Skipping Session!\n", i);
        continue;
      }

      if (config_setting_lookup_int(sn, "PeerPort", &peerPort)) {
        if ((uint32_t)peerPort & 0xffff0000) {
          bfdLog(LOG_ERR, "Session %d PeerPort out of range: %d - Skipping Session!\n",
                 i, peerPort);
          continue;
        }
      } else {
        peerPort = 3784;
      }

      if (config_setting_lookup_int(sn, "LocalPort", &localport)) {
        if ((uint32_t)localport & 0xffff0000) {
          bfdLog(LOG_ERR, "Session %d LocalPort out of range: %d - Skipping Session!\n",
                 i, localport);
          continue;
        }
      } else {
        localport = 3784;
      }

      if (!config_setting_lookup_bool(sn, "DemandMode", &demandMode)) {
        demandMode = 0;
      }

      if (config_setting_lookup_int(sn, "DetectMult", &detectMult)) {
        if ((uint32_t)detectMult & 0xffffff00) {
          bfdLog(LOG_ERR, "Session %d DetectMult out of range: %d - Skipping Session!\n",
                 i, localport);
          continue;
        }
      } else {
        detectMult = BFD_DEFDETECTMULT;
      }

      if (!config_setting_lookup_int(sn, "RequiredMinRxInterval", &reqMinRx)) {
        reqMinRx = BFD_DEFREQUIREDMINRX;
      }

      if (!config_setting_lookup_int(sn, "DesiredMinTxInterval", &desMinTx)) {
        desMinTx = BFD_DEFDESIREDMINTX;
      }

      bfdLog(LOG_NOTICE,
             "BFD[%d]: demandModeDesired %s, detectMult %d, desiredMinTx %d, requiredMinRx %d\n",
             i, (demandMode ? "on" : "off"), detectMult, desMinTx, reqMinRx);

      /* Make UDP socket to receive control packets */
      setupRcvSocket((uint16_t)localport);

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

      bfd->demandModeDesired = (uint8_t)demandMode;
      bfd->detectMult        = (uint8_t)detectMult;
      bfd->upMinTx           = (uint32_t)desMinTx;
      bfd->requiredMinRx     = (uint32_t)reqMinRx;
      bfd->peer              = peeraddr;
      bfd->peerPort          = (uint16_t)peerPort;
      // bfd->remoteDiscr = 0;

      if (!bfdInitSession(bfd)) {
        bfdLog(LOG_ERR, "Can't create initial session: %m\n");
        exit(1);
      }
    }
  }

  config_destroy(&cfg);

  /* Wait for events */
  tpDoEventLoop();

  /* Should never return */
  exit(1);
}
