#include <stdio.h>
#include <netdb.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <inttypes.h>

#include "bfdmonClient.h"
#include "bfd-monitor.h"

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
 * Returns a file descriptor for a socket connected to the montiro
 * server.
 * Return -1 on error.
 */
int bfdmonClient_init(const char *monitor_server)
{
    bfdmonClientDebug("bfdmon: Initializing\n");

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

void bfdmonClient_SubscribeSession(int sock, bfdSession *sn)
{
    int len;
    ssize_t sent;
    char buf[1024];
    char opts[512];

    bfdmonClientInfo("Subscribing to Session: %s\n", sn->SnIdStr);

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
        return;
    }

    bfdmonClientDebug("Sent %zd of %d bytes of subscription request.\n",
                      sent, len);
}

void bfdmonClient_UnsubscribeSession(int sock, bfdSession *sn)
{
    int len;
    ssize_t sent;
    char buf[1024];

    bfdmonClientInfo("Unsubscribing from Session: %s\n", sn->SnIdStr);

    len = snprintf(buf, sizeof(buf), BfdJsonMsgFmt, "Unsubscribe",
                   sn->PeerAddrStr, sn->PeerPort, sn->LocalAddrStr,
                   sn->LocalPort, "");

    sent = sendall(sock, buf, len);
    if (sent < 0)
    {
        bfdmonClientErr("Error sending unsubscribe request: %s\n",
                        strerror(errno));
        return;
    }

    bfdmonClientDebug("Sent %zd of %d bytes of unsubscribe request.\n",
                      sent, len);
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

    /* TODO: Process notify json data */

    return res;
}
