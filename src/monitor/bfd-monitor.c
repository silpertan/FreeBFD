#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <json.h>

#include "avl.h"
#include "bfd.h"
#include "tp-timers.h"
#include "bfd-monitor.h"
#include "bfdLog.h"

#define BUF_SZ 1024

/* A SessionID uniquely identifies a session and is used to create the
   bfdSession object. */

typedef struct SessionID {
  uint16_t localPort;
  uint16_t peerPort;
  const char *localIP;
  const char *peerIP;
} SessionID_t;


/* A Monitor is unique for a given (Connection, SessionID) pair. Each
   Monitor is referenced in a table for the Connection and in a table
   for the Session it is monitoring. If the Connction is closed, all
   Monitors associated with that Connection will be removed from
   associated Session monitor list (if the session's monitor list
   becomes empty, the session will be closed). */

typedef struct Monitor {
  int sock;
  SessionID_t sid;

  // If -1, then all sessions??? NULL, not subscribed yet. If
  // non-NULL, not modified by subscribe API.
  bfdSession *bfd;
} Monitor_t;

/* Each monitor Connection needs to keep a list of all the Monitors
   that were created via that connection. If the connection is closed,
   all of those Monitors must be removed. Memory for Monitor objects
   is managed/owned here (session object just gets a reference). */

typedef struct Connection {
  int sock;
  avl_tree *monitorTree;
} Connection_t;

static avl_tree *connectionTree;

static int bfdMonitorSessionIdCompare(SessionID_t *s1, SessionID_t *s2)
{
    int cmp = 0;

    if (s1->peerIP && s2->peerIP) {
        cmp = strcmp(s1->peerIP, s2->peerIP);
    } else if (s1->peerIP) {
        cmp = 1;
    } else if (s2->peerIP) {
        cmp = -1;
    }

    if (cmp == 0) {
        if (s1->localIP && s2->localIP) {
            cmp = strcmp(s1->localIP, s2->localIP);
        } else {
            if (s1->localIP) {
                cmp = 1;
            } else if (s2->localIP) {
                cmp = -1;
            }
        }
    }

    if (cmp == 0) {
        cmp = s1->peerPort - s2->peerPort;
        if (cmp == 0) {
            cmp = s1->localPort - s2->localPort;
        }
    }

    return cmp;
}

static int bfdMonitorCompare(const void *v1, const void *v2, void *param)
{
    Monitor_t *m1 = (Monitor_t *)v1;
    Monitor_t *m2 = (Monitor_t *)v2;

    if (m1->sock == m2->sock) {
      return bfdMonitorSessionIdCompare(&m1->sid, &m2->sid);
    }

    return (m1->sock - m2->sock);
}

static Monitor_t *bfdMonitorCreateCopy(Monitor_t *other)
{
  Monitor_t *mon = (Monitor_t *)calloc(sizeof(Monitor_t), 1);
  if (!mon) {
    bfdLog(LOG_ERR, "Failed to malloc() a Monitor.\n");
    exit(1);
  }

  mon->sock = other->sock;
  mon->sid.localPort = other->sid.localPort;
  mon->sid.peerPort  = other->sid.peerPort;
  mon->sid.localIP   = strdup(other->sid.localIP);
  mon->sid.peerIP    = strdup(other->sid.peerIP);

  return mon;
}

static void bfdMonitorDestroy(Monitor_t *mon)
{
  if (mon) {
    free((void *)mon->sid.localIP);
    free((void *)mon->sid.peerIP);

    // TODO: Free up bfd session object if needed. There might be some
    // goofy logic here if we want to have a monitor which watches all
    // sessions.
  }

  free(mon);
}

/* Used by avl_destroy() to remove all nodes from the tree. */
static void bfdMonitorDestroyNode(void *data, void *param)
{
  Monitor_t *mon = (Monitor_t *)data;
  bfdMonitorDestroy(mon);
}

static int bfdMonitorConnectionCompare(const void *v1, const void *v2,
                                       void *param)
{
  Connection_t *c1 = (Connection_t *)v1;
  Connection_t *c2 = (Connection_t *)v2;

  return c1->sock - c2->sock;
}

static Connection_t *bfdMonitorConnectionCreate(int sock)
{
  Connection_t *conn = (Connection_t *)calloc(sizeof(Connection_t), 1);
  if (!conn) {
    bfdLog(LOG_ERR, "Failed to malloc() a Connection.\n");
    exit(1);
  }

  conn->sock = sock;
  conn->monitorTree = avl_create(bfdMonitorCompare, NULL);

  avl_insert(connectionTree, conn);

  return conn;
}

static void bfdMonitorConnectionClose(Connection_t *conn)
{
  if (conn) {
    avl_delete(connectionTree, conn);

    close(conn->sock);
    tpRmSktActor(conn->sock);
    bfdLog(LOG_INFO, "MONITOR[%d]: connection closed\n", conn->sock);

    /* Remove all Monitors associated with this connection. */
    avl_destroy(conn->monitorTree, bfdMonitorDestroyNode);

    free(conn);
  }
}

static void bfdMonitorProcessSessionId(json_object *jso, SessionID_t *sid)
{
  json_object *sid_jso;
  json_object *item;

  json_object_object_get_ex(jso, "SessionID", &sid_jso);
  if (!sid_jso) {
    bfdLog(LOG_ERR, "Missing 'SessionID' in json packet\n");
    return;
  }

  sid->peerIP = NULL;
  json_object_object_get_ex(sid_jso, "PeerIP", &item);
  if (item) {
    sid->peerIP = json_object_get_string(item);
  }

  sid->localIP = NULL;
  json_object_object_get_ex(sid_jso, "LocalIP", &item);
  if (item) {
    sid->localIP = json_object_get_string(item);
  }

  sid->peerPort = 0;
  json_object_object_get_ex(sid_jso, "PeerPort", &item);
  if (item) {
    sid->peerPort = (uint16_t)(json_object_get_int(item) & 0xffff);
  }

  sid->localPort = 0;
  json_object_object_get_ex(sid_jso, "LocalPort", &item);
  if (item) {
    sid->localPort = (uint16_t)(json_object_get_int(item) & 0xffff);
  }

  bfdLog(LOG_INFO, "SessionID gathered:\n");
  bfdLog(LOG_INFO, "  PeerIP is '%s'\n", sid->peerIP);
  bfdLog(LOG_INFO, "  LocalIP is '%s'\n", sid->localIP);
  bfdLog(LOG_INFO, "  PeerPort is '%d'\n", sid->peerPort);
  bfdLog(LOG_INFO, "  LocalPort is '%d'\n", sid->localPort);
}

typedef void (*CmdHandler_t)(Connection_t *conn, json_object *jso);

typedef struct CmdEntry {
  const char *name;
  CmdHandler_t handler;
} CmdEntry_t;

static void handler_Subscribe(Connection_t *conn, json_object *jso)
{
  Monitor_t find[1] = {{ .sock = conn->sock }};
  Monitor_t *mon;

  bfdLog(LOG_INFO, "Processing 'Subscribe' command\n");
  bfdMonitorProcessSessionId(jso, &find->sid);

  // Look for an existing subscription on this connection.
  mon = avl_find(conn->monitorTree, find);
  if (!mon) {
    // This is a new subscription request.
    mon = bfdMonitorCreateCopy(find);
    avl_insert(conn->monitorTree, mon);
    // TODO: Subscribe to session. May create a session or attach to an existing session.
    bfdLog(LOG_DEBUG, "MONITOR: created monitor\n");
  } else {
    bfdLog(LOG_DEBUG, "MONITOR: monitor already exists\n");
  }
}

static void handler_Unsubscribe(Connection_t *conn, json_object *jso)
{
  Monitor_t find[1] = {{ .sock = conn->sock }};
  Monitor_t *mon;

  bfdLog(LOG_INFO, "Processing 'Unsubscribe' command\n");
  bfdMonitorProcessSessionId(jso, &find->sid);

  mon = avl_delete(conn->monitorTree, find);
  if (mon) {
    // TODO: Unsubscribe from a session.

    bfdMonitorDestroy(mon);
    bfdLog(LOG_DEBUG, "MONITOR: destroyed monitor\n");
  }
}

static const CmdEntry_t cmdTable[] = {
  { .name = "Subscribe",   .handler = handler_Subscribe },
  { .name = "Unsubscribe", .handler = handler_Unsubscribe },

  /* Terminator */
  { .name = NULL, .handler = NULL }
};

static void bfdMonitorProcessCmd(Connection_t *conn, const char *cmd,
                                 json_object *jso)
{
  const CmdEntry_t *ent = cmdTable;

  while (ent->name) {
    if (strcmp(ent->name, cmd) == 0) {
      ent->handler(conn, jso);
      return;
    }
    ent++;
  }

  bfdLog(LOG_ERR, "MONITOR: Unknown command: %s\n", cmd);
}

/* NOTE: Must do a json_object_put(obj) when done with an object to
   decrement reference count. Otherwise, it's memory leak time. */

static void bfdMonitorProcessPkt(Connection_t *conn, char *buf)
{
  json_object *obj = json_tokener_parse(buf);

  if (!obj) {
    bfdLog(LOG_ERR, "failed to parse json\n");
    return;
  }

  json_object *cmd_obj;

  json_object_object_get_ex(obj, "MsgType", &cmd_obj);

  if (cmd_obj) {
    const char *cmd = json_object_get_string(cmd_obj);
    bfdMonitorProcessCmd(conn, cmd, obj);
  } else {
    bfdLog(LOG_ERR, "expected 'MsgType' in json not found\n");
  }

  json_object_put(obj);
}

static void bfdMonitorRecvPkt(int sock, void *arg)
{
  ssize_t res;
  char buf[BUF_SZ+1];
  Connection_t *conn = (Connection_t *)arg;

  res = read(sock, buf, BUF_SZ);

  if (res < 0) {
    if (errno == EINTR)
      return;

    bfdLog(LOG_ERR, "Monitor failed in read(): %m\n");
  } else if (res == 0) {
    /* EOF on stream. Close connection and remove actor. */
    bfdMonitorConnectionClose(conn);
  } else {
    // The read() is unlikely to terminate the string.
    buf[res] = '\0';

    bfdLog(LOG_INFO, "MONITOR[%d]: READ[%zd]: '%s'\n", sock, res, buf);

    bfdMonitorProcessPkt(conn, buf);
  }
}

/*
 * Process a new connection on monitor server.
 */
static void bfdMonitorConnection(int server, void *arg)
{
  int sock;
  Connection_t *conn;

  if ((sock = accept(server, (struct sockaddr *)NULL, NULL)) < 0) {
    bfdLog(LOG_ERR, "Failed call to accept(): %m\n");
    return;
  }

  conn = bfdMonitorConnectionCreate(sock);

  bfdLog(LOG_DEBUG, "MONITOR[%d]: connection opened\n", sock);

  tpSetSktActor(sock, bfdMonitorRecvPkt, conn, NULL);
}

/*
 * Create and register server socket to receive monitor connections.
 */
void bfdMonitorSetupServer(uint16_t port)
{
  struct sockaddr_in sin;
  int sock;
  int optval = 1;

  connectionTree = avl_create(bfdMonitorConnectionCompare, NULL);

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
