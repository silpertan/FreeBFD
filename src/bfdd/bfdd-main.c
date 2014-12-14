#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <inttypes.h>
#include "bfd.h"
#include "bfd-monitor.h"
#include "bfdLog.h"
#include "bfdd.h"
#include "tp-timers.h"

/*
 * Command line usage info
 */
static void bfddUsage(void)
{
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "\tbfdd [options] [-c <config-file>] [-d] [-m port] [-v]\n");
  fprintf(stderr, "Where:\n");
  fprintf(stderr, "\t-c: load 'config-file' for startup configuration\n");
  fprintf(stderr, "Options:\n");
  fprintf(stderr, "\t-d: Do not run in daemon mode\n");
  fprintf(stderr, "\t-m port: Port monitor server will listen on (default %d)\n",
          DEFAULT_MONITOR_PORT);
  fprintf(stderr, "\t-v: increase level of debug output (can be repeated)\n");
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
  char *configFile = NULL;
  int daemon_mode = 1;
  uint16_t monitor_port = DEFAULT_MONITOR_PORT;

  bfdLogInit();

  /* Get command line options */
  while ((c = getopt(argc, argv, "c:dm:v")) != -1) {
    switch (c) {
    case 'c':
      configFile = optarg;
      break;
    case 'd':
      daemon_mode = 0;
      break;
    case 'm':
      if (sscanf(optarg, "%" SCNu16, &monitor_port) != 1) {
        fprintf(stderr, "Expected integer for monitor port.\n");
        bfddUsage();
        exit(1);
      }
      break;
    case 'v':
      bfdLogMore();
      break;
    default:
      bfddUsage();
      exit(1);
    }
  }

  if (daemon_mode) {
    if (daemon(1, 0) != 0) {
      bfdLog(LOG_ERR, "Unable to daemonize!");
      exit(1);
    }
  }

  /* Init random() */
  srandom((unsigned int)time(NULL));

  /* Init timers package */
  tpInitTimers();

  /* Set signal handlers */
  tpSetSignalActor(bfdStartPollSequence, SIGUSR1);
  tpSetSignalActor(bfdToggleAdminDown, SIGUSR2);

  if (!bfdd_handleConfigFile(configFile)) {
    fprintf(stderr, "Error parsing config file\n");
    exit(1);
  }

  bfdMonitorSetupServer(monitor_port);

  /* Wait for events */
  tpDoEventLoop();

  /* Should never return */
  exit(1);
}
