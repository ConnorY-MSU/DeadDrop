#ifndef MSGLOG_H
#define MSGLOG_H

#include <stddef.h>

/* msglog - small, local, append-only log of chat messages so a reboot/crash doesn't lose the conversation. Plaintext, protected only by 0600 perms - see COMMENT_ARCHIVE.md. */

#define MSGLOG_LINE_MAX 600 /* Bounds only the REPLAY buffer (msglog_load_recent()); the log file itself keeps the full line via msglog_append(). */

/* msglog_append - append one timestamped line ("[YYYY-MM-DD HH:MM:SS] who: text\n"); `who` may be NULL. Best-effort, failures not reported. */
void msglog_append(const char *who, const char *text);

/* msglog_append_saved - same as msglog_append(), but marks the line SAVED so it survives a future msglog_clear_except_saved(). */
void msglog_append_saved(const char *who, const char *text);

/* msglog_clear_except_saved - the "/clear" command's effect: rewrites the log in place, keeping only SAVED lines. Best-effort, failure not reported. */
void msglog_clear_except_saved(void);

/* msglog_destroy_all - the "/destroy CONFIRM" panic-wipe's log-side effect; unlike msglog_clear_except_saved(), removes EVERYTHING. See COMMENT_ARCHIVE.md. */
void msglog_destroy_all(void);

/* msglog_load_recent - fill out_lines with up to max_lines most recent log entries (oldest first). Returns the number of lines filled. */
int msglog_load_recent(char out_lines[][MSGLOG_LINE_MAX], int max_lines);

#endif /* MSGLOG_H */
