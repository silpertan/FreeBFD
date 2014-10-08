#include <stdio.h>
#include <netdb.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

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
    printf("bfdmon: Initializing\n");

    return inetConnect(monitor_server, DEFAULT_MONITOR_PORT);
}
