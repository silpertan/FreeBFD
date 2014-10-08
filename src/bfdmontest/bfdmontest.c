#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <inttypes.h>

#include "bfd.h"
#include "bfdmonClient.h"

const char *UsageFmtStr =
    "Usage: %s <monitor-host> <session-file>\n"
    "\n"
    "A session file is just a list of sessions, one session per line.\n"
    "Each line has the following format:\n"
    "\n"
    "  '<peer-addr> <peer-port> <local-addr> <local-port> [<session-opts>]\n"
    "\n"
    "Where <session-opts> are key=value pairs with the following keys:\n"
    "\n"
    "  DemandMode=<on|off>\n"
    "  DetectMult=<int>\n"
    "  DesiredMinTx=<int>\n"
    "  RequiredMinRx=<int>\n"
    "\n"
    "NOTE: The <local-addr> and <local-port> refer to the local address and\n"
    "port on the system running the monitor server (aka the BFDD daemon),\n"
    "not the system running the monitor client application (they may not be\n"
    "the same system).\n"
    ;

Session *load_session_file(const char *fname)
{
    char line[1024];
    bfdSession sn[1];
    Session *sn_list = NULL;
    char *p;
    Session *psn;

    FILE *fp = fopen(fname, "r");
    if (!fp)
    {
        fprintf(stderr, "Error opening session file: %s: %s\n",
                fname, strerror(errno));
        exit(1);
    }

    while (fgets(line, sizeof(line), fp) != NULL)
    {
        int n;
        size_t len = strlen(line);

        memset(sn, 0, sizeof(sn));

        sn->DemandMode = BFDDFLT_DEMANDMODE;
        sn->DetectMult = BFDDFLT_DETECTMULT;
        sn->DesiredMinTxInterval = BFDDFLT_DESIREDMINTX;
        sn->RequiredMinRxInterval = BFDDFLT_REQUIREDMINRX;

        /* Parse out the peer and local addresses and ports. Order is
           fixed and all are required. */
        if (sscanf(line, "%15s %"SCNu16" %15s %"SCNu16"%n", sn->PeerAddrStr,
                   &sn->PeerPort, sn->LocalAddrStr, &sn->LocalPort, &n) == 4)
        {
            psn = (Session *)malloc(sizeof(Session));
            if (!psn)
            {
                fprintf(stderr, "Failed to malloc Session\n");
                exit(1);
            }

            memcpy(&psn->bfd, sn, sizeof(bfdSession));

            psn->next = sn_list;
            sn_list = psn;

            /* Parse out the session options. They can be in any order, or not present. */
            p = line + n;
            while (p < (line + len))
            {
                char opt[20];
                char val[10];
                if (sscanf(p, "%*[ ]%20[^=]=%10s%n", opt, val, &n) != 2) {
                    break;
                }

                p += n;

                if (strcmp("DemandMode", opt) == 0) {
                    psn->bfd.DemandMode = (strcmp("on", val) == 0);
                }
                if (strcmp("DetectMult", opt) == 0) {
                    if (sscanf(val, "%"SCNu8, &psn->bfd.DetectMult) != 1)
                        fprintf(stderr, "Error converting DetectMult to uint8\n");
                }
                if (strcmp("DesiredMinTx", opt) == 0) {
                    if (sscanf(val, "%"SCNu32, &psn->bfd.DesiredMinTxInterval) != 1)
                        fprintf(stderr, "Error converting DesiredMinTx to uint32\n");
                }
                if (strcmp("RequiredMinRx", opt) == 0) {
                    if (sscanf(val, "%"SCNu32, &psn->bfd.RequiredMinRxInterval) != 1)
                        fprintf(stderr, "Error converting RequiredMinRx to uint32\n");
                }
            }
        }
    }

    fclose(fp);

    return sn_list;
}

void dump_session_list(Session *psn)
{
    while (psn)
    {
        bfdSession *sn = &psn->bfd;
        printf("Session: peer=%s:%"PRIu16" local=%s:%"PRIu16" "
               "DemandMode=%s DetectMult=%"PRIu8" DesiredMinTx=%"PRIu32" "
               "RequiredMinRx=%"PRIu32"\n",
               sn->PeerAddrStr, sn->PeerPort, sn->LocalAddrStr,
               sn->LocalPort, sn->DemandMode ? "on": "off", sn->DetectMult,
               sn->DesiredMinTxInterval, sn->RequiredMinRxInterval);
        psn = psn->next;
    }
}

int main(int argc, char **argv)
{
    const char *monitor_server;
    Session *sn_list;
    int sock;

    if (argc != 3)
    {
        fprintf(stderr, UsageFmtStr, argv[0]);
        exit(2);
    }

    monitor_server = argv[1];
    sn_list = load_session_file(argv[2]);
    dump_session_list(sn_list);

    printf("Starting bfdmontest application.\n");
    sock = bfdmonClient_init(monitor_server);
    if (sock < 0)
    {
        fprintf(stderr, "Failed to connect to monitor server.\n");
        exit(3);
    }

    sleep(3);
    close(sock);

    return 0;
}

/* Logging function needed by the bfdmon client library */
void bfdmonClientLog(BfdMonLogLvl lvl, const char *file, int line,
                     const char *fmt, ...)
{
    va_list ap;
    const char *lvlStr = bfdmonClientLogLvlStr(lvl);

    fprintf(stderr, "[%s: %s: %d] ", lvlStr, file, line);

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}
