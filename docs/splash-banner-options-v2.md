# Splash banner design options, round 2

**UPDATE (2026-08-23): Option F chosen and implemented, then upsized.** Direct request came with a real question worth checking, not assuming: are both devices actually still on the smaller 66x20 constraint this document was written against? Checked directly on both real devices (`stty -F /dev/tty1 size`, `fbset`) - **no**, both now report 100 cols x 30 rows and a genuine 1280x720 framebuffer. `bravo`'s earlier smaller reading really was the "DSI auto-detection flakiness" `TESTING.md`'s own investigation had already flagged as the more likely explanation over a permanent hardware difference - it resolved itself across this session's several real reboots. Since neither device is actually constrained to 66x20 anymore, Option F below was scaled up (two 14-char boxes instead of 8-char, a 34-char connector instead of a short one, 78 cols wide overall) to make real use of the now-confirmed 100-col width, and colored: green for the ALPHA box, yellow for BRAVO, cyan for the connector (`CP_NODE_ALPHA`/`CP_NODE_BRAVO`, new dedicated color pairs - see `src/ui.c`). Verified for real on hardware: not just the text layout via `/dev/vcs1`, but the actual color attribute bytes via `/dev/vcsa1` (decoded byte-for-byte, confirming the Linux console's raw attribute encoding is CGA-ordered, not ANSI-ordered - a real, non-obvious distinction worth documenting for next time). The original 41x9 mockup below is kept for the record; the deployed version is larger.

Five new, more dramatic concepts for `show_splash()` (`src/ui.c`), on top of the original five in `docs/splash-banner-options.md`.

**Why a second round:** the original five were only verified against `alpha`'s console (100 cols x 30 rows). This session confirmed `bravo`'s console is genuinely smaller - 66 cols x 20 rows (a real physical panel resolution difference, not a config bug - see `TESTING.md`'s DSI resolution investigation). Every option below is verified - programmatically (`awk`, not by hand-counting) - against the **smaller** 66x20 constraint, with real margin to spare in every case, so whichever one you pick will look right on both devices without needing per-device logic.

**Same font constraint as before:** `Lat15-Terminus24x12` is a codepage font, not full Unicode - no box-drawing glyphs, no guaranteed symbol coverage beyond plain printable ASCII (0x20-0x7E). Every option below uses only that range - checked, not assumed.

Pick a letter (or mix pieces of two, like last time) and I'll wire it into `show_splash()`.

---

## Option F: Twin Nodes
**41 cols x 9 rows** - the two paired devices, shown literally, linked by name.

```
 +-------+                      +-------+
 | ALPHA |====== LINKED ========| BRAVO |
 +-------+                      +-------+

            S E C U R E L I N K

         [ ENCRYPTED FIELD TERMINAL ]

           ( tap screen to continue )
```

**Vibe:** the most conceptually honest option of the five - it literally shows what the product *is* (two named devices, linked) rather than an abstract logo. Anyone watching it boot immediately understands the pairing relationship without reading a word of documentation. Compact, narrow, leaves the most vertical breathing room of any option here.

---

## Option G: Signal Bars
**37 cols x 11 rows** - ascending WiFi-style signal bars feeding into a framed wordmark.

```
                       _
                      |#|
                    _ |#|
                   |#||#|
                 _ |#||#|
                |#||#||#|
     .__________|#||#||#|__________.
     |      S E C U R E L I N K    |
     |   [ ENCRYPTED FIELD TERM ]  |
     '______________________________'
           ( tap screen to continue )
```

**Vibe:** the most thematically on-the-nose for this exact project, given how much of this session was spent on WiFi hotswap/scan reliability - literal signal bars "landing" on the terminal like a live connection indicator. Reads as energetic and tech-forward, not just decorative.

---

## Option H: Vault Rivets
**51 cols x 7 rows** - a heavy, bolted double-line frame with rivet marks in the corners.

```
   ###############################################
   #  o                                       o  #
   #         S E C U R E L I N K                 #
   #      [ ENCRYPTED FIELD TERMINAL ]            #
   #  o                                       o  #
   ###############################################
              ( tap screen to continue )
```

**Vibe:** the most "physically secure" feeling of the five - dense `#` border reads heavier/tougher than a thin `=` or `-` line, and the corner `o` marks suggest an actual bolted vault door rather than just a decorative box. Shortest option vertically (7 rows) - would sit compact and centered with a lot of empty space above/below on the larger `alpha` console, which could look either intentional (confident, minimal) or a little lost depending on taste.

---

## Option I: Terminal Boot
**52 cols x 8 rows** - fake boot-log lines leading into the wordmark, styled like a real Linux service startup.

```
   root@deaddrop:~$ initializing mTLS session...
   root@deaddrop:~$ tailscale mesh......... [ OK ]
   root@deaddrop:~$ key-share reconstruct.. [ OK ]

            >> S E C U R E L I N K <<
             encrypted field terminal

           [ tap screen to continue ]
```

**Vibe:** the most "authentic hacker terminal" of the five, and a little bit winking about it - it's showing a *fake* boot log on a device that's genuinely, literally booting on a real Linux terminal at that exact moment. Widest option (52 cols) but still comfortable margin on both consoles. Best pick if you want it to look like something out of a spy-thriller field kit rather than a polished commercial product.

---

## Option J: Chevron Convergence
**45 cols x 7 rows** - arrows converging inward from both sides onto the name, suggesting a secure tunnel closing around the data.

```
   >>>                                    <<<
    >>>                                  <<<
     >>>      S E C U R E L I N K       <<<
    >>>     [ ENCRYPTED FIELD TERM ]     <<<
   >>>                                    <<<

           ( tap screen to continue )
```

**Vibe:** the most dynamic/kinetic-feeling of the five despite being a static screen - the converging chevrons suggest motion and "closing in" around the protected name, evoking the encrypted-tunnel concept directly. Compact (7 rows), reads fast at a glance.

---

## Implementation notes (same as round 1)
- All five reuse the existing `ui_draw_hline()`/`ui_draw_centered()` helpers where applicable, plus plain `mvwprintw()` for the freeform ones (Signal Bars, Terminal Boot) - a contained change to `show_splash()`, not a rewrite.
- Dismiss hint (`tap screen to continue`) included in every mockup, matching the real on-screen behavior.
- Verified dimensions (`awk`, exact character counts per line) against 66 cols x 20 rows, the smaller of the two real console sizes - every option has real margin (smallest margin: Option I at 52/66 cols, 8/20 rows; every other option has more room than that).
- Character set: confirmed plain-ASCII only (0x20-0x7E) across all five - no box-drawing, no extended symbols, matching `Lat15-Terminus24x12`'s actual glyph coverage.
