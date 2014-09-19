#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <json.h>

#include "bfd.h"
#include "tp-timers.h"
#include "bfd-monitor.h"
#include "bfdLog.h"

#define BUF_SZ 1024

typedef struct MonitorInfo {
  int sock;
} MonitorInfo_t;

typedef void (*CmdHandler_t)(json_object *jso, MonitorInfo_t *mon);

typedef struct CmdEntry {
  const char *name;
  CmdHandler_t handler;
} CmdEntry_t;

static void handler_Subscribe(json_object *jso, MonitorInfo_t *mon)
{
  bfdLog(LOG_INFO, "Processing 'subscribe' command\n");
}

static void handler_Unsubscribe(json_object *jso, MonitorInfo_t *mon)
{
  bfdLog(LOG_INFO, "Processing 'unsubscribe' command\n");
}

static const CmdEntry_t cmdTable[] = {
  { .name = "subscribe",   .handler = handler_Subscribe },
  { .name = "unsubscribe", .handler = handler_Unsubscribe },

  /* Terminator */
  { .name = NULL, .handler = NULL }
};

static void bfdMonitorProcessCmd(const char *cmd, json_object *jso,
                                 MonitorInfo_t *mon)
{
  const CmdEntry_t *ent = cmdTable;

  while (ent->name) {
    if (strcmp(ent->name, cmd) == 0) {
      ent->handler(jso, mon);
      return;
    }
    ent++;
  }

  bfdLog(LOG_ERR, "MONITOR: Unknown command: %s\n", cmd);
}

/* NOTE: Must do a json_object_put(obj) when done with an object to
   decrement reference count. Otherwise, it's memory leak time. */

static void bfdMonitorProcessPkt(char *buf, MonitorInfo_t *mon)
{
  json_object *obj = json_tokener_parse(buf);

  if (!obj) {
    bfdLog(LOG_ERR, "failed to parse json\n");
    return;
  }

  json_object *cmd_obj;

  json_object_object_get_ex(obj, "cmd", &cmd_obj);

  if (cmd_obj) {
    const char *cmd = json_object_get_string(cmd_obj);
    bfdMonitorProcessCmd(cmd, obj, mon);
  } else {
    bfdLog(LOG_ERR, "expected 'cmd' in json not found\n");
  }

  json_object_put(obj);
}

static void bfdMonitorRecvPkt(int sock, void *arg)
{
  ssize_t res;
  char buf[BUF_SZ+1];
  MonitorInfo_t *mon = NULL; // TODO: create a mon-info instance. This
                             // may not be the right place to do it.

  res = read(sock, buf, BUF_SZ);

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
    // The read() is unlikely to terminate the string.
    buf[res] = '\0';

    bfdLog(LOG_INFO, "MONITOR[%d]: READ[%zd]: '%s'\n", sock, res, buf);

    // TODO: Start session? Most likely will start a session when a
    // command pkt comes over the connection.
    // TODO: Parse buffer and dispatch commands. Command Pattern?
    bfdMonitorProcessPkt(buf, mon);
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
