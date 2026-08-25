# Splash banner design options

Five options for the boot splash (`show_splash()` in `src/ui.c`), now that it sticks around until the screen is tapped instead of a fixed 1.2s display (see `TESTING.md`/commit history for that change).

**Dimensions, confirmed against the real hardware, not assumed:** the deployed console is **100 columns x 30 rows** (`stty size` on `/dev/tty1` with the `Lat15-Terminus24x12` font). Every option below is verified — programmatically, not by hand-counting — to fit within `COLS-2` (98) columns wide and comfortably inside 30 rows, with margin to spare in every case. The width/height noted under each option's heading is its actual measured size.

**Font constraint:** `Lat15-Terminus24x12` is a codepage font, not a full Unicode font — this project has already established (see `ui.c`'s STYLING comment) that real box-drawing/Unicode glyphs have no verified glyph coverage on it. Every option below uses **plain ASCII only** (`#`, `=`, `-`, `+`, `|`, `/`, `\`, `.`, `_`) — nothing here needs a font upgrade or a fallback path to actually render correctly.

Pick a letter (or mix pieces of two) and I'll wire it into `show_splash()`.

---

## Option A: Enhanced Classic Framed
**74 cols x 9 rows** — the current design, evolved: a wider double-line box, explicit dismiss hint built into the frame.

```
+========================================================================+
|                                                                        |
|                          S E C U R E L I N K                           |
|                                                                        |
|                      [ ENCRYPTED FIELD TERMINAL ]                      |
|                                                                        |
|                       ( tap screen to continue )                       |
|                                                                        |
+========================================================================+
```

**Vibe:** safe, tasteful, close to what's already there — lowest visual risk, most "professional field equipment" feeling. Good default if you want *some* upgrade without a big departure.

---

## Option B: Big Block Wordmark
**69 cols x 12 rows** — a real block-letter logotype, hand-verified letter by letter (not a font you have to trust blindly).

```
 ##### ######  ##### ##  ## #####  ###### ##     ###### ##   # ##  ##
##     ##     ##     ##  ## ##  ## ##     ##       ##   ###  # ## ## 
##     ##     ##     ##  ## ##  ## ##     ##       ##   #### # ####  
 ####  #####  ##     ##  ## #####  #####  ##       ##   ## ### ###   
    ## ##     ##     ##  ## ## ##  ##     ##       ##   ##  ## ####  
    ## ##     ##     ##  ## ##  ## ##     ##       ##   ##  ## ## ## 
#####  ######  #####  ####  ##  ## ###### ###### ###### ##  ## ##  ##

                    [ ENCRYPTED FIELD TERMINAL ]

                     ( tap screen to continue )
```

**Vibe:** the most dramatic, "this is a real piece of equipment booting up" option — biggest visual impact of the five. Takes the most vertical real estate but still leaves ~18 rows free.

---

## Option C: Shield/Lock Icon + Wordmark
**28 cols x 17 rows** — a small ASCII padlock/shield above the name, narrower and taller than the others.

```
          _______           
         /       \          
        /  .---.  \         
       |  /     \  |        
       | |   #   | |        
       | |  ###  | |        
       |  \_____/  |        
        \    |    /         
         \   |   /          
          \  |  /           
           \ | /            
            \|/             

    S E C U R E L I N K     
[ ENCRYPTED FIELD TERMINAL ]

 ( tap screen to continue )
```

**Vibe:** literal, immediate "this is a secure/encrypted device" signal via the icon itself, not just the text. Most compact horizontally — leaves the most side margin of any option, would look centered and deliberate rather than stretched across the screen.

---

## Option D: Tactical HUD Frame
**80 cols x 12 rows** — a wide, understated rectangular frame with generous internal padding, evoking a targeting/HUD readout rather than a decorative box.

```
+------------------------------------------------------------------------------+
|                                                                              |
|                                                                              |
|                                  DEADDROP                                  |
|                                                                              |
|                         [ ENCRYPTED FIELD TERMINAL ]                         |
|                                                                              |
|                                                                              |
|                          ( tap screen to continue )                          |
|                                                                              |
|                                                                              |
+------------------------------------------------------------------------------+
```

**Vibe:** matches "FIELD TERMINAL" branding most literally — spacious, quiet, technical rather than decorative. The single-line `-` border reads as more "instrument panel" than Option A's `=` border.

---

## Option E: Minimalist Boot-Log Style
**46 cols x 6 rows** — deliberately understated, reads like genuine boot output rather than a splash screen at all.

```

DeadDrop v1.0 -- encrypted field terminal
----------------------------------------------

  [ tap screen to continue ]

```

**Vibe:** the contrarian option — if the other four feel too "showy" for a security tool, this is the anti-banner: quiet, credible, no ceremony. Also the cheapest to render (smallest, fastest to eyeball-verify against real hardware).

---

## Implementation notes (whichever you pick)
- All five reuse the already-built `ui_draw_hline()`/`ui_draw_centered()` helpers where applicable (A/D's borders), so wiring in a choice is a small, contained change to `show_splash()` — not a rewrite.
- The dismiss hint text is already wired to the real tap-to-continue behavior (just added) — every option above includes it in the mockup so what you're choosing between is honest about the final on-screen result, not just the "logo" part in isolation.
- Color: current palette applies `CP_BANNER` (white) to the frame/title and `CP_ACCENT` (cyan) to the subtitle — happy to adjust per-option if one of these would look better with a different split (e.g., Option C's icon in a different color from the wordmark).
