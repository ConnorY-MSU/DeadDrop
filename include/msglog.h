#ifndef MSGLOG_H
#define MSGLOG_H

#include <stddef.h>

/*
 * msglog - a small, local, append-only log of real chat messages (not
 * every system/connection notice - see session.c's call sites), so a
 * reboot or crash doesn't lose the whole conversation the way the
 * previously purely-in-memory ncurses history did.
 *
 * Lives at $HOME/.securelink/message_log.txt - deliberately the SAME
 * directory the PIN hash already uses (see lock.c's
 * lock_pin_file_path()), which means it's automatically covered by
 * the existing Week 4 Day 5 overlay-persistence bind mount with zero
 * changes needed to docs/setup-persist-overlay.sh.
 *
 * HONEST, DELIBERATE LIMITATION - stated plainly, not glossed over:
 * this file is stored in PLAINTEXT, protected only by 0600 file
 * permissions and this device's own physical/OS-level security - the
 * same tradeoff this project already accepts for the overlay/
 * persistence design generally (see Documentation Standard's known-
 * limitations guidance). Real encryption-at-rest for message content
 * would need its own key-management story (the private key's mutual
 * key-share protection, Week 4 Day 4, doesn't apply here - that key
 * changes per reconnect via the TLS exporter, unsuitable for
 * encrypting something meant to persist across many sessions). Not
 * attempted here; documented as a real gap instead.
 */

#define MSGLOG_LINE_MAX 600 /* generous: "[YYYY-MM-DD HH:MM:SS] " (22) +
    a peer label + a full UI_INPUT_MAX (2048)-sized message would
    exceed this - deliberately truncates a very long line rather than
    trying to hold an entire 2KB message verbatim in the REPLAY buffer;
    the full, untruncated line is still what actually gets written to
    the log FILE itself (see msglog_append()) - this cap only bounds
    what msglog_load_recent() hands back for on-screen replay at
    startup. */

/*
 * msglog_append - append one timestamped line ("[YYYY-MM-DD HH:MM:SS]
 * who: text\n") to the log. `who` may be NULL for a message with no
 * prefix (matches ui_add_history()'s own convention). Best-effort: a
 * failure to open/write the log file is not reported to the caller -
 * this is a convenience/persistence feature, not something that should
 * ever be able to interrupt an actual message exchange.
 */
void msglog_append(const char *who, const char *text);

/*
 * msglog_append_saved - same as msglog_append(), but marks the line as
 * SAVED (a "[SAVED] " marker written right after the timestamp, before
 * `who`) - see msglog_clear_except_saved()'s comment for what this
 * marker actually protects. Intended for a message the user explicitly
 * flagged (see session.c's "/save <text>" command) as worth keeping
 * through a future /clear, not for general use.
 */
void msglog_append_saved(const char *who, const char *text);

/*
 * msglog_clear_except_saved - the "/clear" command's actual effect
 * (see session.c): rewrites the log file in place, keeping ONLY lines
 * previously written via msglog_append_saved() and discarding
 * everything else. This is a real, on-disk zeroing (not just a
 * clear of what's currently on screen) - the whole point of the
 * feature is that plaintext chat content (see this header's top
 * comment on the honest at-rest limitation) doesn't have to sit
 * around indefinitely if the user wants it gone. Best-effort, same
 * as msglog_append() - a failure here is not reported to the caller,
 * though ui.c still shows a confirmation notice either way since the
 * caller (session.c) doesn't have a failure signal to act on
 * differently.
 */
void msglog_clear_except_saved(void);

/*
 * msglog_load_recent - fill out_lines with up to max_lines of the most
 * RECENT entries from the log (oldest of the returned lines first,
 * matching natural reading order), each already formatted exactly as
 * written by msglog_append() (so the caller can display them directly,
 * e.g. via ui_add_history(NULL, out_lines[i])). Returns the number of
 * lines actually filled (0 if the log doesn't exist yet or is empty).
 */
int msglog_load_recent(char out_lines[][MSGLOG_LINE_MAX], int max_lines);

#endif /* MSGLOG_H */
