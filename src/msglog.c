#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "msglog.h"

#ifdef _WIN32
    #include <direct.h>
    #define MKDIR(path) _mkdir(path)
#else
    #include <sys/stat.h>
    #include <sys/types.h>
    #define MKDIR(path) mkdir((path), 0700)
#endif

/* Same $HOME-based path convention as lock.c's lock_pin_file_path() -
 * see msglog.h's top comment for why this specific directory. */
static int msglog_file_path(char *buf, size_t buf_size)
{
    const char *home = getenv("HOME");
#ifdef _WIN32
    if (home == NULL) {
        home = getenv("USERPROFILE");
    }
#endif
    if (home == NULL) {
        return -1;
    }
    if ((size_t)snprintf(buf, buf_size, "%s/.securelink/message_log.txt",
                          home) >= buf_size) {
        return -1;
    }
    return 0;
}

/* Same minimal "create the parent directory" helper as lock.c's
 * ensure_pin_dir() - not shared/exported between the two files, same
 * reasoning as every other small module in this project (wifi.c,
 * touch.c, hw_*.c) not sharing helpers either; it's a few lines,
 * duplicating it is cheaper than introducing cross-module coupling for
 * something this small. */
static void ensure_log_dir(const char *log_path)
{
    char dir[512];
    char *slash;

    if (snprintf(dir, sizeof(dir), "%s", log_path) >= (int)sizeof(dir)) {
        return;
    }
    slash = strrchr(dir, '/');
    if (slash == NULL) {
        return;
    }
    *slash = '\0';
    MKDIR(dir);
}

/* Written right after the timestamp, before `who`, on a line saved via
 * msglog_append_saved() - see msglog.h's comment on both that function
 * and msglog_clear_except_saved(), which greps for exactly this string
 * to decide what survives a /clear. Kept human-readable on purpose (it
 * shows up as-is in the replayed history, same as everything else in
 * this file) rather than some non-printing sentinel. */
#define MSGLOG_SAVED_MARKER "[SAVED] "

static void msglog_append_ex(const char *who, const char *text, int saved)
{
    char path[512];
    FILE *f;
    time_t now;
    struct tm tm_now;
    char timestamp[32];

    if (msglog_file_path(path, sizeof(path)) != 0) {
        return;
    }
    ensure_log_dir(path);

    f = fopen(path, "a");
    if (f == NULL) {
        return; /* best-effort - see this function's header comment */
    }

    now = time(NULL);
#ifdef _WIN32
    localtime_s(&tm_now, &now);
#else
    localtime_r(&now, &tm_now);
#endif
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &tm_now);

    if (who != NULL) {
        fprintf(f, "[%s] %s%s: %s\n", timestamp,
                saved ? MSGLOG_SAVED_MARKER : "", who,
                text != NULL ? text : "");
    } else {
        fprintf(f, "[%s] %s%s\n", timestamp,
                saved ? MSGLOG_SAVED_MARKER : "", text != NULL ? text : "");
    }
    fclose(f);

#ifndef _WIN32
    chmod(path, 0600); /* owner read/write only, matches the PIN hash
        file's own precedent in the same directory - see msglog.h's
        top comment on the honest plaintext-at-rest limitation this
        permission bit is the only real protection for. */
#endif
}

void msglog_append(const char *who, const char *text)
{
    msglog_append_ex(who, text, 0);
}

void msglog_append_saved(const char *who, const char *text)
{
    msglog_append_ex(who, text, 1);
}

void msglog_clear_except_saved(void)
{
    char path[512];
    char tmp_path[520];
    FILE *in;
    FILE *out;
    char line[MSGLOG_LINE_MAX + 64]; /* generous over MSGLOG_LINE_MAX -
        a log LINE written by msglog_append_ex() isn't itself capped to
        MSGLOG_LINE_MAX (that cap only bounds what msglog_load_recent()
        hands back for REPLAY - see msglog.h), so this needs its own
        independent margin to avoid truncating a genuinely long line
        while filtering, not reuse of the replay-side constant. */

    if (msglog_file_path(path, sizeof(path)) != 0) {
        return;
    }
    if ((size_t)snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", path) >=
            sizeof(tmp_path)) {
        return;
    }

    in = fopen(path, "r");
    if (in == NULL) {
        return; /* no log yet - nothing to clear, not an error */
    }
    out = fopen(tmp_path, "w");
    if (out == NULL) {
        fclose(in);
        return;
    }

    while (fgets(line, sizeof(line), in) != NULL) {
        /* A saved line looks like "[YYYY-MM-DD HH:MM:SS] [SAVED] ...";
         * strstr() (rather than checking a fixed offset) is deliberate -
         * it stays correct regardless of exact timestamp width and
         * doesn't need to duplicate the timestamp format used above. */
        if (strstr(line, MSGLOG_SAVED_MARKER) != NULL) {
            fputs(line, out);
        }
    }

    fclose(in);
    fclose(out);

#ifndef _WIN32
    chmod(tmp_path, 0600);
#endif
    /* Atomically replace the old log with the filtered one - either the
     * old file or the fully-written new one is what's on disk at any
     * point, never a half-written file (rename() on POSIX and Windows
     * with an existing destination target is not literally atomic on
     * every filesystem, but is the closest portable primitive available
     * here, and is the same guarantee every other "write to a temp file,
     * then swap it in" pattern in this codebase relies on). */
#ifdef _WIN32
    remove(path); /* Windows rename() fails if the destination exists */
#endif
    rename(tmp_path, path);
}

void msglog_destroy_all(void)
{
    char path[512];
    FILE *f;

    if (msglog_file_path(path, sizeof(path)) != 0) {
        return;
    }

    /* Best-effort overwrite before delete - see msglog.h's own comment
     * on this function for the honest limitation (not a guaranteed
     * secure erase on flash storage). "r+b" so this is a no-op (fopen
     * fails, nothing to overwrite) if the log doesn't exist yet -
     * matches every other function in this file treating "no log yet"
     * as a normal, non-error state. */
    f = fopen(path, "r+b");
    if (f != NULL) {
        long size;
        if (fseek(f, 0, SEEK_END) == 0 && (size = ftell(f)) > 0) {
            char zeros[4096];
            long remaining = size;
            memset(zeros, 0, sizeof(zeros));
            fseek(f, 0, SEEK_SET);
            while (remaining > 0) {
                size_t chunk = (size_t)(remaining < (long)sizeof(zeros)
                                             ? remaining
                                             : (long)sizeof(zeros));
                if (fwrite(zeros, 1, chunk, f) != chunk) {
                    break; /* best-effort - a partial overwrite is still
                        strictly better than none, keep going to the
                        remove() below regardless */
                }
                remaining -= (long)chunk;
            }
            fflush(f);
        }
        fclose(f);
    }

    remove(path);
}

/* Read at most this many trailing bytes of the log file when looking
 * for recent lines - bounds memory use even if the log has grown very
 * large over a long deployment, at the cost of possibly missing lines
 * older than this window on a single call (acceptable: this is a
 * "show recent context on boot" convenience, not a full-log viewer -
 * every line, recent or not, is still in the actual file on disk). */
#define MSGLOG_TAIL_READ_BYTES 65536

int msglog_load_recent(char out_lines[][MSGLOG_LINE_MAX], int max_lines)
{
    char path[512];
    FILE *f;
    long file_size;
    long read_size;
    char *buf;
    int total_lines = 0;
    char *line_starts[512]; /* generous upper bound on how many lines
        MSGLOG_TAIL_READ_BYTES could plausibly contain, given real
        chat-message line lengths - a defensive cap, not a tight one */
    char *saveptr = NULL;
    char *line;
    int start_idx;
    int filled = 0;
    int i;

    if (out_lines == NULL || max_lines <= 0) {
        return 0;
    }
    if (msglog_file_path(path, sizeof(path)) != 0) {
        return 0;
    }

    f = fopen(path, "rb");
    if (f == NULL) {
        return 0; /* no log yet - a normal, expected first-run state */
    }

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return 0;
    }
    file_size = ftell(f);
    if (file_size <= 0) {
        fclose(f);
        return 0;
    }

    read_size = file_size;
    if (read_size > MSGLOG_TAIL_READ_BYTES) {
        read_size = MSGLOG_TAIL_READ_BYTES;
    }
    if (fseek(f, file_size - read_size, SEEK_SET) != 0) {
        fclose(f);
        return 0;
    }

    buf = malloc((size_t)read_size + 1);
    if (buf == NULL) {
        fclose(f);
        return 0;
    }
    {
        size_t got = fread(buf, 1, (size_t)read_size, f);
        buf[got] = '\0';
    }
    fclose(f);

    /* Split into lines, remembering each line's start pointer - the
     * first "line" is likely a partial line (we may have started
     * reading mid-line, since read_size can cut the file off anywhere)
     * and is deliberately dropped below rather than shown truncated. */
    line = strtok_r(buf, "\n", &saveptr);
    while (line != NULL && total_lines < (int)(sizeof(line_starts) /
                                                 sizeof(line_starts[0]))) {
        line_starts[total_lines++] = line;
        line = strtok_r(NULL, "\n", &saveptr);
    }

    /* Drop the first (likely-partial) line, UNLESS we read the whole
     * file from its true beginning (read_size == file_size), in which
     * case even the first line is genuinely complete. */
    start_idx = (read_size < file_size && total_lines > 0) ? 1 : 0;
    if (total_lines - start_idx > max_lines) {
        start_idx = total_lines - max_lines;
    }

    for (i = start_idx; i < total_lines; i++) {
        snprintf(out_lines[filled], MSGLOG_LINE_MAX, "%s", line_starts[i]);
        filled++;
    }

    free(buf);
    return filled;
}
