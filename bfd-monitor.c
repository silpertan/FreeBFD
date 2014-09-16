#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>

#include "bfd.h"
#include "tp-timers.h"
#include "bfd-monitor.h"

#define BUF_SZ 1024

static void bfdMonitorRecvPkt(int sock, void *arg)
{
  ssize_t res;
  char buf[BUF_SZ+1];

  res = read(sock, buf, BUF_SZ);
  buf[BUF_SZ] = '\0';

  if (res < 0) {
    if (errno == EINTR)
      return;

    bfdLog(LOG_ERR, "Monitor failed in read(): %m\n");
  } else if (res == 0) {
    /* EOF on stream. Close connection and remove actor. */
    close(sock);
    tpRmSktActor(sock);
    bfdLog(LOG_INFO, "MONITOR[%d]: connection closed\n", sock);
  } else {
    bfdLog(LOG_INFO, "MONITOR[%d]: READ[%zd]: '%s'\n", sock, res, buf);

    // TODO: Start session? Most likely will start a session when a
    // command pkt comes over the connection.
    // TODO: Parse buffer and dispatch commands. Command Pattern?
  }
}

/*
 * Process a new connection on monitor server.
 */
static void bfdMonitorConnection(int server, void *arg)
{
  int conn;

  if ((conn = accept(server, (struct sockaddr *)NULL, NULL)) < 0) {
    bfdLog(LOG_ERR, "Failed call to accept(): %m\n");
    return;
  }

  bfdLog(LOG_INFO, "MONITOR[%d]: connection opened\n", conn);

  tpSetSktActor(conn, bfdMonitorRecvPkt, NULL, NULL);
}

/*
 * Create and register server socket to receive monitor connections.
 */
void bfdMonitorSetupServer(uint16_t port)
{
  struct sockaddr_in sin;
  int sock;
  int optval = 1;

  if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    bfdLog(LOG_ERR, "Can't get monitor socket: %m\n");
    exit(1);
  }

  if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
    bfdLog(LOG_ERR, "Can't set socket option REUSEADDR: %m\n");
    exit(1);
  }

  sin.sin_family      = AF_INET;
  sin.sin_addr.s_addr = INADDR_ANY;
  sin.sin_port        = htons(port);

  if (bind(sock, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
    bfdLog(LOG_ERR, "Can't bind socket to port %d: %m\n", port);
    exit(1);
  }

  if (listen(sock, 5) < 0) {
    bfdLog(LOG_ERR, "Can't listen on socket: %m\n");
    exit(1);
  }

  bfdLog(LOG_INFO, "Waiting for Monitor connections\n");

  /* Add socket to select poll. */
  tpSetSktActor(sock, bfdMonitorConnection, NULL, NULL);
}
