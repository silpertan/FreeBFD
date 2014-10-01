#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <json.h>
#include <arpa/inet.h>

#include "avl.h"
#include "bfd.h"
#include "tp-timers.h"
#include "bfd-monitor.h"
#include "bfdLog.h"

#define BUF_SZ 1024

/* A Monitor is unique for a given (Connection, SessionID) pair. Each
   Monitor is referenced in a table for the Connection and in a table
   for the Session it is monitoring. If the Connction is closed, all
   Monitors associated with that Connection will be removed from
   associated Session monitor list (if the session's monitor list
   becomes empty, the session will be closed). */

typedef struct Monitor {
  int sock;
  bfdSession Sn;
  bfdSubHndl *bfdSubHandle;
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

static int bfdMonitorSessionIdCompare(bfdSession *s1, bfdSession *s2)
{
  int cmp = (int)(s1->PeerAddr.s_addr) - (int)(s2->PeerAddr.s_addr);

    if (cmp == 0) {
      cmp = (int)(s1->LocalAddr.s_addr) - (int)(s2->LocalAddr.s_addr);
    }

    if (cmp == 0) {
      cmp = s1->PeerPort - s2->PeerPort;
    }

    if (cmp == 0) {
      cmp = s1->LocalPort - s2->LocalPort;
    }

    return cmp;
}

static int bfdMonitorCompare(const void *v1, const void *v2, void *param)
{
    Monitor_t *m1 = (Monitor_t *)v1;
    Monitor_t *m2 = (Monitor_t *)v2;

    int cmp = m1->sock - m2->sock;

    if (cmp == 0) {
      return bfdMonitorSessionIdCompare(&m1->Sn, &m2->Sn);
    }

    return cmp;
}

static Monitor_t *bfdMonitorCreateCopy(Monitor_t *other)
{
  Monitor_t *mon = (Monitor_t *)calloc(sizeof(Monitor_t), 1);
  if (!mon) {
    bfdLog(LOG_ERR, "Failed to malloc() a Monitor.\n");
    exit(1);
  }

  memcpy(mon, other, sizeof(Monitor_t));

  return mon;
}

static void bfdMonitorDestroy(Monitor_t *mon)
{
  if (mon) {
    bfdLog(LOG_DEBUG, "MONITOR[%d]: destroying monitor: Peer=%s:%d, "
           "Local=%s:%d\n", mon->sock, mon->Sn.PeerAddrStr, mon->Sn.PeerPort,
           mon->Sn.LocalAddrStr, mon->Sn.LocalPort);

    free(mon);
  }
}

/* Used by avl_destroy() to remove all nodes from the tree. */
static void bfdMonitorDestroyNode(void *data, void *param)
{
  Monitor_t *mon = (Monitor_t *)data;
  bfdUnsubscribe(mon->bfdSubHandle);
  bfdMonitorDestroy(mon);
}

/* Callback to be installed in session via bfdSubscribe() during
   subscribe operation. */
static void bfdMonitorNotify(bfdState state, void *arg)
{
  Monitor_t *mon = (Monitor_t *)arg;

  // TODO: send out notification to connected monitor application.
  bfdLog(LOG_DEBUG, "MONITOR[%d]: Sending notification: Peer=%s:%d "
         "Local=%s:%d State=%s\n",
         mon->sock, mon->Sn.PeerAddrStr, mon->Sn.PeerPort,
         mon->Sn.LocalAddrStr, mon->Sn.LocalPort, bfdStateToStr(state));
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

/*
 * Returns 0 on success, -1 on failure to extract session id from json.
 */
static int bfdMonitorProcessSessionId(json_object *jso, bfdSession *sn)
{
  json_object *sid_jso;
  json_object *item;
  const char *str;

  json_object_object_get_ex(jso, "SessionID", &sid_jso);
  if (!sid_jso) {
    bfdLog(LOG_ERR, "Missing 'SessionID' in json packet\n");
    return -1;
  }

  sn->PeerAddr.s_addr = 0;
  json_object_object_get_ex(sid_jso, "PeerIP", &item);
  if (item) {
    str = json_object_get_string(item);
    if (inet_aton(str, &sn->PeerAddr) == 0) {
      bfdLog(LOG_ERR, "Failed to convert 'PeerIP' to IP address: %s\n", str);
      return -1;
    } else {
      strncpy(sn->PeerAddrStr, inet_ntoa(sn->PeerAddr), BFD_ADDR_STR_SZ);
    }
  } else {
    bfdLog(LOG_ERR, "Missing 'PeerIP' in json packet\n");
    return -1;
  }

  /* All of the following are optional, do not generate an error on
     failure to convert. */

  sn->LocalAddr.s_addr = INADDR_ANY;
  json_object_object_get_ex(sid_jso, "LocalIP", &item);
  if (item) {
    str = json_object_get_string(item);
    if (inet_aton(str, &sn->LocalAddr) == 0) {
      bfdLog(LOG_WARNING, "Failed to convert 'LocalIP' to IP address: %s\n",
             str);
    } else {
      strncpy(sn->LocalAddrStr, inet_ntoa(sn->LocalAddr), BFD_ADDR_STR_SZ);
      /* TODO: Need to check if local addr is associated with an interface. */
    }
  } else {
    bfdLog(LOG_INFO, "Missing optional 'LocalIP' in json packet\n");
  }

  sn->PeerPort = 0;
  json_object_object_get_ex(sid_jso, "PeerPort", &item);
  if (item) {
    sn->PeerPort = (uint16_t)(json_object_get_int(item) & 0xffff);
  }

  sn->LocalPort = 0;
  json_object_object_get_ex(sid_jso, "LocalPort", &item);
  if (item) {
    sn->LocalPort = (uint16_t)(json_object_get_int(item) & 0xffff);
  }

  bfdLog(LOG_INFO, "SessionID gathered:\n");
  bfdLog(LOG_INFO, "  PeerIP is '%s'\n", sn->PeerAddrStr);
  bfdLog(LOG_INFO, "  LocalIP is '%s'\n", sn->LocalAddrStr);
  bfdLog(LOG_INFO, "  PeerPort is '%d'\n", sn->PeerPort);
  bfdLog(LOG_INFO, "  LocalPort is '%d'\n", sn->LocalPort);

  return 0;
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
  bfdSubHndl sub;

  bfdLog(LOG_INFO, "Processing 'Subscribe' command\n");

  if (bfdMonitorProcessSessionId(jso, &find->Sn) < 0) {
    bfdLog(LOG_WARNING, "MONITOR: unable to extract session id from json.\n");
    return;
  }

  // Look for an existing subscription on this connection.
  mon = avl_find(conn->monitorTree, find);
  if (!mon) {
    // This is a new subscription request.
    mon = bfdMonitorCreateCopy(find);
    sub = bfdSubscribe(&mon->Sn, bfdMonitorNotify, mon);
    if (sub) {
      mon->bfdSubHandle = sub;
      avl_insert(conn->monitorTree, mon);
      bfdLog(LOG_DEBUG, "MONITOR[%d]: created monitor\n", conn->sock);
    } else {
      bfdMonitorDestroy(mon);
      bfdLog(LOG_DEBUG, "MONITOR[%d]: failed to subscribe monitor.\n",
             conn->sock);
    }
  } else {
    bfdLog(LOG_DEBUG, "MONITOR[%d]: monitor already exists\n", conn->sock);
  }
}

static void handler_Unsubscribe(Connection_t *conn, json_object *jso)
{
  Monitor_t find[1] = {{ .sock = conn->sock }};
  Monitor_t *mon;

  bfdLog(LOG_INFO, "MONITOR[%d] Processing 'Unsubscribe' command\n", conn->sock);

  if (bfdMonitorProcessSessionId(jso, &find->Sn) < 0) {
    bfdLog(LOG_WARNING, "MONITOR[%d]: unable to extract session id from json.\n",
           conn->sock);
    return;
  }

  mon = avl_delete(conn->monitorTree, find);
  if (mon) {
    bfdUnsubscribe(mon->bfdSubHandle);
    bfdMonitorDestroy(mon);
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

  bfdLog(LOG_ERR, "MONITOR[%d]: Unknown command: %s\n", conn->sock, cmd);
}

/* NOTE: Must do a json_object_put(obj) when done with an object to
   decrement reference count. Otherwise, it's memory leak time. */

static void bfdMonitorProcessPkt(Connection_t *conn, char *buf)
{
  json_object *obj = json_tokener_parse(buf);

  if (!obj) {
    bfdLog(LOG_ERR, "MONITOR[%d] failed to parse json\n", conn->sock);
    return;
  }

  json_object *cmd_obj;

  json_object_object_get_ex(obj, "MsgType", &cmd_obj);

  if (cmd_obj) {
    const char *cmd = json_object_get_string(cmd_obj);
    bfdMonitorProcessCmd(conn, cmd, obj);
  } else {
    bfdLog(LOG_ERR, "MONITOR[%d] expected 'MsgType' in json not found\n",
           conn->sock);
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

    bfdLog(LOG_ERR, "MONITOR[%d] failed in read(): %m\n", sock);
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
    bfdLog(LOG_ERR, "MONITOR: Failed call to accept(): %m\n");
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
    bfdLog(LOG_ERR, "MONITOR: Can't get monitor socket: %m\n");
    exit(1);
  }

  if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
    bfdLog(LOG_ERR, "MONITOR: Can't set socket option REUSEADDR: %m\n");
    exit(1);
  }

  sin.sin_family      = AF_INET;
  sin.sin_addr.s_addr = INADDR_ANY;
  sin.sin_port        = htons(port);

  if (bind(sock, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
    bfdLog(LOG_ERR, "MONITOR: Can't bind socket to port %d: %m\n", port);
    exit(1);
  }

  if (listen(sock, 5) < 0) {
    bfdLog(LOG_ERR, "MONITOR: Can't listen on socket: %m\n");
    exit(1);
  }

  bfdLog(LOG_INFO, "MONITOR: Waiting for connections\n");

  /* Add socket to select poll. */
  tpSetSktActor(sock, bfdMonitorConnection, NULL, NULL);
}
