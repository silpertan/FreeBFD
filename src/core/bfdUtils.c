#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>


#include "bfd.h"

const char *bfdStateToStr(bfdState state)
{
  switch (state) {
    case BFDSTATE_ADMINDOWN: return "AdminDown";
    case BFDSTATE_DOWN:      return "Down";
    case BFDSTATE_INIT:      return "Init";
    case BFDSTATE_UP:        return "Up";

    /* No default so compiler can complain if states are missing. */
  };

  return "Unknown";
}

/*
 * Converts a string into a bfdState.
 *
 * Return 0 on successful conversion, -1 on failure.
 */
int bfdStateFromStr(bfdState *state, const char *str)
{
  if (strcmp(str, "AdminDown") == 0)
    *state = BFDSTATE_ADMINDOWN;
  else if (strcmp(str, "Down") ==0)
    *state = BFDSTATE_DOWN;
  else if (strcmp(str, "Init") == 0)
    *state = BFDSTATE_INIT;
  else if (strcmp(str, "Up") == 0)
    *state = BFDSTATE_UP;
  else
    return -1;

  return 0;
}


/*
 * Must be called immediately after the PeerAddr, LocalAddr, PeerPort
 * and LocalPort fields have been set.
 */
void bfdSessionSetStrings(bfdSession *bfd)
{
    snprintf(bfd->PeerAddrStr, BFD_ADDR_STR_SZ, "%s", inet_ntoa(bfd->PeerAddr));
    snprintf(bfd->LocalAddrStr, BFD_ADDR_STR_SZ, "%s", inet_ntoa(bfd->LocalAddr));

    /* Can not call inet_ntoa() twice in arguments to a function since
       it uses a static internal buffer and always return the same
       pointer (i.e. the second overwrites the buffer). */

    snprintf(bfd->SnIdStr, BFD_SN_ID_STR_SZ, "peer=%s:%d local=%s:%d",
             bfd->PeerAddrStr, bfd->PeerPort, bfd->LocalAddrStr, bfd->LocalPort);
}

int bfdSessionCompare(bfdSession *s1, bfdSession *s2)
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
