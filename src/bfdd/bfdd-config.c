#include <libconfig.h>
#include <inttypes.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "bfd.h"
#include "bfdLog.h"
#include "bfdd.h"

bool bfdd_handleConfigFile(const char* cfgFile)
{
  config_t cfg;
  config_setting_t *sns;

  config_init(&cfg);

  /* Read the file */
  if(!config_read_file(&cfg, cfgFile)) {
    bfdLog(LOG_ERR, "Error loading config file [%s]: %s:%d - %s\n",
           cfgFile,
           config_error_file(&cfg),
           config_error_line(&cfg),
           config_error_text(&cfg));

    config_destroy(&cfg);

    return false;
  }

  /* Parse configured sessions */
  if ((sns = config_lookup(&cfg, "Sessions")) != NULL) {
    int32_t cnt = config_setting_length(sns);
    uint32_t i;

    for (i=0; i<cnt; i++) {
      struct hostent *hp;
      struct in_addr peeraddr;
      struct in_addr localaddr = { .s_addr = INADDR_ANY };
      const char *connectaddr = NULL;
      int32_t peerPort;
      int32_t localport;
      int32_t demandMode;
      int32_t detectMult;
      int32_t reqMinRx;
      int32_t desMinTx;
      bfdSession bfd;

      config_setting_t *sn = config_setting_get_elem(sns, i);
      config_setting_t *ext = config_setting_get_member(sn, "Ext");

      if (!config_setting_lookup_string(sn, "PeerAddress", &connectaddr)) {
        bfdLog(LOG_WARNING,
               "Session %d missing PeerAddress - Skipping Session!\n", i);
        continue;
      }

      if (ext && config_setting_lookup_int(ext, "PeerPort", &peerPort)) {
        if ((uint32_t)peerPort & 0xffff0000) {
          bfdLog(LOG_WARNING,
                 "Session %d PeerPort out of range: %d - Skipping Session!\n",
                 i, peerPort);
          continue;
        }
      } else {
        peerPort = BFDDFLT_UDPPORT;
      }

      if (ext && config_setting_lookup_int(ext, "LocalPort", &localport)) {
        if ((uint32_t)localport & 0xffff0000) {
          bfdLog(LOG_WARNING, "Session %d LocalPort out of range: %d - Skipping Session!\n",
                 i, localport);
          continue;
        }
      } else {
        localport = BFDDFLT_UDPPORT;
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
        detectMult = BFDDFLT_DETECTMULT;
      }

      if (!config_setting_lookup_int(sn, "RequiredMinRxInterval", &reqMinRx)) {
        reqMinRx = BFDDFLT_REQUIREDMINRX;
      }

      if (!config_setting_lookup_int(sn, "DesiredMinTxInterval", &desMinTx)) {
        desMinTx = BFDDFLT_DESIREDMINTX;
      }

      bfdLog(LOG_NOTICE,
             "BFD[%d]: demandModeDesired %s, detectMult %d, desiredMinTx %d, requiredMinRx %d\n",
             i, (demandMode ? "on" : "off"), detectMult, desMinTx, reqMinRx);

      /* Get peer address */
      if ((hp = gethostbyname(connectaddr)) == NULL) {
        bfdLog(LOG_ERR, "Can't resolve %s - Skipping Session %d: %s\n",
               connectaddr, i, hstrerror(h_errno));
        continue;
      }

      if (hp->h_addrtype != AF_INET) {
        bfdLog(LOG_ERR, "Resolved address type for session %d not AF_INET - Skipping Session\n", i);
        continue;
      }

      memcpy(&peeraddr, hp->h_addr, sizeof(peeraddr));

      memset(&bfd, 0, sizeof(bfdSession));

      bfd.DemandMode            = (uint8_t)(demandMode & 0x1);
      bfd.DetectMult            = (uint8_t)detectMult;
      bfd.DesiredMinTxInterval  = (uint32_t)desMinTx;
      bfd.RequiredMinRxInterval = (uint32_t)reqMinRx;
      bfd.PeerAddr              = peeraddr;
      bfd.LocalAddr             = localaddr;
      bfd.PeerPort              = (uint16_t)peerPort;
      bfd.LocalPort             = (uint16_t)localport;

      bfdSessionSetStrings(&bfd);

      bfdLog(LOG_INFO, "Creating session %d with %s (%s)\n", i, connectaddr,
             bfd.SnIdStr);

      if (!bfdCreateSession(&bfd)) {
        bfdLog(LOG_ERR, "Can't create session %d: %m\n", i);
        continue;
      }
    }
  }

  config_destroy(&cfg);

  return true;
}
