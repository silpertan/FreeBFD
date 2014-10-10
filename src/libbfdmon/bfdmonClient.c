#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <inttypes.h>
#include <json.h>
#include <arpa/inet.h>

#include "bfdmonClient.h"
#include "bfd-monitor.h"
#include "avl.h"

struct Subscription_ {
    bfdSession *sn;
    BfdMonNotifyCallback notify_cb;
    void *cb_arg;
};
typedef struct Subscription_ Subscription;

/* Container for subscriptions. */
avl_tree *subscriptionTree;

static int bfdmonClient_SubscriptionCompare(const void *v1, const void *v2,
                                            void *param)
{
    Subscription *s1 = (Subscription *)v1;
    Subscription *s2 = (Subscription *)v2;

    return bfdSessionCompare(s1->sn, s2->sn);
}

const char *bfdmonClientLogLvlStr(BfdMonLogLvl lvl)
{
    switch (lvl)
    {
        case BFDMON_LOG_DEBUG: return "DEBUG";
        case BFDMON_LOG_INFO:  return "INFO";
        case BFDMON_LOG_WARN:  return "WARN";
        case BFDMON_LOG_ERR:   return "ERROR";
    }
    return "Unknown";
}

/*
 * Returns the socket for the connection to the server on success.
 * Returns -1 on error.
 */
static int inetConnect(const char *host, uint16_t portNum)
{
    int res;
    int sock;
    char port[10];
    struct addrinfo hints;
    struct addrinfo *result;
    struct addrinfo *rp;

    snprintf(port, sizeof(port), "%"PRIu16, portNum);

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_canonname = NULL;
    hints.ai_addr = NULL;
    hints.ai_next = NULL;
    hints.ai_family = AF_INET; /* IPv4: use AF_UNSPEC to support both IPv4 & IPv6 */
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags= AI_NUMERICSERV;

    if ((res = getaddrinfo(host, port, &hints, &result)) != 0)
    {
        bfdmonClientErr("getaddrinfo: %s\n", gai_strerror(res));
        return -1;
    }

    /* Walk returned list until a connection is made. */

    for (rp = result; rp; rp = rp->ai_next)
    {
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock < 0)
            continue;           /* Try next address. */

        if (connect(sock, rp->ai_addr, rp->ai_addrlen) >= 0)
            return sock;        /* Success! */

        bfdmonClientErr("connect() failed: %s\n", strerror(errno));
        close(sock);
    }

    bfdmonClientErr("Could not connect to server: %s:%s\n", host, port);
    return -1;
}

/*
 * Returns a file descriptor for a socket connected to the monitor
 * server.
 * Return -1 on error.
 */
int bfdmonClient_init(const char *monitor_server)
{
    bfdmonClientDebug("bfdmon: Initializing\n");

    if (!subscriptionTree)
    {
        subscriptionTree = avl_create(bfdmonClient_SubscriptionCompare, NULL);
    }

    return inetConnect(monitor_server, DEFAULT_MONITOR_PORT);
}

ssize_t sendall(int sock, char *buf, int len)
{
    ssize_t n;
    size_t bytes_pend = (size_t)len;
    size_t bytes_sent = 0;

    while (bytes_sent < bytes_pend) {
        n = send(sock, buf+bytes_sent, bytes_pend, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) { continue; }

            return -1;          /* Let caller report errno. */
        }

        bytes_sent += (size_t)n;
        bytes_pend -= (size_t)n;
    }

    return (ssize_t)bytes_sent;
}

const char *BfdJsonMsgFmt =
    "{"
    " \"MsgType\":\"%s\","
    " \"SessionID\": {"
        " \"PeerAddr\":\"%s\","
        " \"PeerPort\":%d,"
        " \"LocalAddr\":\"%s\","
        " \"LocalPort\":%d"
        " }"
    "%s"  // Session options.
    " }";

const char *BfdSessionOptsFmt =
    ", \"SessionOpts\": {"
    " \"DemandMode\":\"%s\","
    " \"DetectMult\":%"PRIu8","
    /*" \"AuthType\":%"PRIu8","*/
    " \"DesiredMinTxInterval\":%"PRIu32","
    " \"RequiredMinRxInterval\":%"PRIu32""
    " }";

/* TODO: Need to add a callback mechanism here and a structure to
   track all subscriptions. */

void bfdmonClient_SubscribeSession(int sock, bfdSession *sn,
                                   BfdMonNotifyCallback notify_cb, void *cb_arg)
{
    int len;
    ssize_t sent;
    char buf[1024];
    char opts[512];
    Subscription find[1] = {{ .sn = sn }};
    Subscription *psub;

    psub = avl_find(subscriptionTree, find);
    if (psub)
    {
        bfdmonClientInfo("Already subscribed to Session: %s\n", sn->SnIdStr);
        return;
    }

    bfdmonClientInfo("Subscribing to Session: %s\n", sn->SnIdStr);

    psub = (Subscription *)malloc(sizeof(Subscription));
    if (!psub)
    {
        bfdmonClientErr("malloc() failed\n");
        return;
    }
    psub->sn = (bfdSession *)malloc(sizeof(bfdSession));
    if (!psub->sn)
    {
        bfdmonClientErr("malloc() failed\n");
        free(psub);
        return;
    }

    memcpy(psub->sn, sn, sizeof(bfdSession));
    psub->notify_cb = notify_cb;
    psub->cb_arg = cb_arg;

    snprintf(opts, sizeof(opts), BfdSessionOptsFmt,
             sn->DemandMode ? "on" : "off", sn->DetectMult,
             /*sn->AuthType,*/
             sn->DesiredMinTxInterval, sn->RequiredMinRxInterval);

    len = snprintf(buf, sizeof(buf), BfdJsonMsgFmt, "Subscribe",
                   sn->PeerAddrStr, sn->PeerPort, sn->LocalAddrStr,
                   sn->LocalPort, opts);

    sent = sendall(sock, buf, len);
    if (sent < 0)
    {
        bfdmonClientErr("Error sending subscription request: %s\n",
                        strerror(errno));

        free(psub->sn);
        free(psub);
        return;
    }

    bfdmonClientDebug("Sent %zd of %d bytes of subscription request.\n",
                      sent, len);

    avl_insert(subscriptionTree, psub);

    bfdmonClientInfo("Subscription to Session succeeded: %s\n", sn->SnIdStr);
}

/* Return -1 on failure to subscribe, 0 if successful. */

int bfdmonClient_UnsubscribeSession(int sock, bfdSession *sn)
{
    int len;
    ssize_t sent;
    char buf[1024];
    Subscription find[1] = {{ .sn = sn }};
    Subscription *psub;

    bfdmonClientInfo("Unsubscribing from Session: %s\n", sn->SnIdStr);

    psub = avl_delete(subscriptionTree, find);
    if (!psub)
    {
        bfdmonClientInfo("Subscription not found for session: %s\n", sn->SnIdStr);
        return -1;
    }

    len = snprintf(buf, sizeof(buf), BfdJsonMsgFmt, "Unsubscribe",
                   psub->sn->PeerAddrStr, psub->sn->PeerPort,
                   psub->sn->LocalAddrStr, psub->sn->LocalPort, "");

    sent = sendall(sock, buf, len);
    if (sent < 0)
    {
        bfdmonClientErr("Error sending unsubscribe request: %s\n",
                        strerror(errno));

        /* Put sub back since we're still subscribed on the server. */
        avl_insert(subscriptionTree, psub);
        return -1;
    }

    bfdmonClientDebug("Sent %zd of %d bytes of unsubscribe request.\n",
                      sent, len);

    free(psub->sn);
    free(psub);

    return 0;
}

static void bfdmonClient_NotifyDispatch(bfdSession *sn, bfdState state)
{
    Subscription find[1] = {{ .sn = sn }};
    Subscription *psub;

    psub = avl_find(subscriptionTree, find);
    if (!psub)
    {
        bfdmonClientInfo("Notify failed, session not in subscriptions: %s\n",
                         sn->SnIdStr);
        return;
    }

    psub->notify_cb(psub->sn, state, psub->cb_arg);
}

static int bfdmonClient_NotifyParseSession(json_object *jso, bfdSession *sn,
                                           bfdState *state)
{
    json_object *jso_obj;
    json_object *item;
    const char *str;

    json_object_object_get_ex(jso, "SessionID", &jso_obj);
    if (!jso_obj)
    {
        bfdmonClientErr("Missing 'SessionID' in json packet\n");
        return -1;
    }

    sn->PeerAddr.s_addr = 0;
    json_object_object_get_ex(jso_obj, "PeerAddr", &item);
    if (item)
    {
        str = json_object_get_string(item);
        if (inet_aton(str, &sn->PeerAddr) == 0)
        {
            bfdmonClientErr("Failed to convert 'PeerAddr' to IP address: %s\n",
                            str);
            return -1;
        }
    }
    else
    {
        bfdmonClientErr("Missing 'PeerAddr' in json packet\n");
        return -1;
    }

    /* All of the following are optional, do not generate an error on
       failure to convert. */

    sn->LocalAddr.s_addr = INADDR_ANY;
    json_object_object_get_ex(jso_obj, "LocalAddr", &item);
    if (item)
    {
        str = json_object_get_string(item);
        if (inet_aton(str, &sn->LocalAddr) == 0)
        {
            bfdmonClientWarn("Failed to convert 'LocalAddr' to IP addr: %s\n",
                             str);
        }
    }

    sn->PeerPort = 0;
    json_object_object_get_ex(jso_obj, "PeerPort", &item);
    if (item)
    {
        sn->PeerPort = (uint16_t)(json_object_get_int(item) & 0xffff);
    }

    sn->LocalPort = 0;
    json_object_object_get_ex(jso_obj, "LocalPort", &item);
    if (item)
    {
        sn->LocalPort = (uint16_t)(json_object_get_int(item) & 0xffff);
    }

    bfdSessionSetStrings(sn);

    bfdmonClientInfo("SessionID from json msg: %s\n", sn->SnIdStr);

    json_object_object_get_ex(jso, "State", &jso_obj);
    if (jso_obj)
    {
        str = json_object_get_string(jso_obj);
        if (bfdStateFromStr(state, str) != 0)
        {
            bfdmonClientErr("failed to convert string to state: %s\n", str);
            return -1;
        }
    }
    else
    {
        bfdmonClientErr("missing 'State' in json packet\n");
        return -1;
    }

    return 0;
}

static void bfdmonClient_NotifyParseAndDispatch(const char *buf)
{
    bfdSession sn[1];
    bfdState state;
    json_object *jso = json_tokener_parse(buf);
    json_object *jso_type;

    if (!jso)
    {
        bfdmonClientWarn("failed to parse json\n");
        return;
    }

    json_object_object_get_ex(jso, "MsgType", &jso_type);
    if (jso_type)
    {
        const char *msg_type = json_object_get_string(jso_type);
        if (strcmp("Notify", msg_type) == 0)
        {
            if (bfdmonClient_NotifyParseSession(jso, sn, &state) == 0)
                bfdmonClient_NotifyDispatch(sn, state);
        }
        else
        {
            bfdmonClientInfo("unknown message type: %s\n", msg_type);
        }
    }
    else
    {
        bfdmonClientInfo("missing 'MsgType' in json\n");
    }

    json_object_put(jso);
}

#define BUF_SZ 1024

/*
 * Reads data from the socket connected to the monitor server.
 *
 * Tries to parse out json notification message and dispatch the
 * notification via the a callback tied to the session at subscribe
 * time.
 *
 * Returns:
 *
 *   <0: Read failed, caller should check errno, may not be recoverable.
 *       The value of errno will be copied into the *p_errno argument.
 *    0: Socket connection was closed by server.
 *   >0: Read data succesfully, caller should just continue.
 */
ssize_t bfdmonClient_NotifyReadAndDispatch(int sock, int *p_errno)
{
    ssize_t res;
    char buf[BUF_SZ+1];

    if (p_errno)
        *p_errno = 0;

    res = read(sock, buf, BUF_SZ);

    if (res < 0)
    {
        if (errno == EINTR)
            return 1;           /* Caller should just continue. */

        if (p_errno)
            *p_errno = errno;   /* Caller will handle errno. */
        else
            bfdmonClientWarn("error in read(): %s\n", strerror(errno));

        return -1;
    }
    else if (res == 0)
    {
        /* EOF on stream. */
        return 0;
    }

    /* Buffer may not have been terminated by read(). */
    if (res && (buf[res-1] == '\n'))
        buf[res-1] = '\0';
    else
        buf[res] = '\0';

    bfdmonClientDebug("RECV: size=%zd: msg='%s'\n", res, buf);

    bfdmonClient_NotifyParseAndDispatch(buf);

    return res;
}
