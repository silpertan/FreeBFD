/*****************************************************************************
 * We use the following log levels generally in the way described:
 *   - Error (LOG_ERR):       program errors, things that have gone wrong
 *                            that need to be fixed, (e.g. we should never
 *                            have gotten into this condition)
 *   - Warning (LOG_WARNING): problems that have been detected that will
 *                            prevent the system or session from working
 *                            as expected (e.g. link is down)
 *   - Notice (LOG_NOTICE):   major protocol/session occurrences (e.g. state
 *                            change, session create/delete)
 *   - Info (LOG_INFO):       more intricate protocol/session operational
 *                            details, per-packet errors
 *   - Debug (LOG_DEBUG):     internal, programmer-level details
 *
 * The default output level is LOG_NOTICE. Calling bfdLogMore() increases
 * the output level by one step (e.g. LOG_WARNING -> LOG_NOTICE).
 *
 ****************************************************************************/

/* Comment this out to prevent logging to stderr */
#define BFD_LOGTOSTDERR

void bfdLogInit(void);
void bfdLogMore(void);
void bfdLog(int lvl, const char *fmt, ...);
