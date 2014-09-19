/*****************************************************************************
 * We use the following log levels:
 *   - Error (LOG_ERR)
 *   - Warning (LOG_WARNING)
 *   - Notice (LOG_NOTICE)
 *   - Info (LOG_INFO)
 *   - Debug (LOG_DEBUG)
 *
 * The default output level is LOG_WARNING. Calling bfdLogMore() increases
 * the output level by one step (e.g. LOG_WARNING -> LOG_NOTICE).
 *
 ****************************************************************************/

/* Comment this out to prevent logging to stderr */
#define BFD_LOGTOSTDERR

void bfdLogInit(void);
void bfdLogMore(void);
void bfdLog(int lvl, const char *fmt, ...);
