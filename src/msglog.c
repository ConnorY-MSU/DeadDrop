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

void msglog_append(const char *who, const char *text)
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
        fprintf(f, "[%s] %s: %s\n", timestamp, who,
                text != NULL ? text : "");
    } else {
        fprintf(f, "[%s] %s\n", timestamp, text != NULL ? text : "");
    }
    fclose(f);

#ifndef _WIN32
    chmod(path, 0600); /* owner read/write only, matches the PIN hash
        file's own precedent in the same directory - see msglog.h's
        top comment on the honest plaintext-at-rest limitation this
        permission bit is the only real protection for. */
#endif
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
