#!/bin/bash
# Bind the text console (VT1) to the DSI touchscreen framebuffer, not
# whichever framebuffer happened to enumerate first.
#
# Real, confirmed-on-hardware issue (see TESTING.md, "DSI console-
# binding fix"): the DSI touchscreen panel and the HDMI output register
# as fb0/fb1 in enumeration order that is NOT guaranteed stable across
# boots, and differed between two otherwise-identical Pi units. If the
# console lands on fb0 and fb0 turns out to be HDMI, the touchscreen
# sits powered but blank while console text goes out a port nothing is
# plugged into. Identifying the DSI framebuffer by its driver NAME
# ("drm-rp1-dsidrmf") rather than assuming a fixed index is what makes
# this fix actually reliable across boots.
set -e

for fb in /sys/class/graphics/fb*; do
    n=$(basename "$fb" | sed 's/fb//')
    name=$(cat "$fb/name" 2>/dev/null || echo "")
    if [ "$name" = "drm-rp1-dsidrmf" ]; then
        con2fbmap 1 "$n"
        exit 0
    fi
done

echo "fix-console-fb: no DSI framebuffer (drm-rp1-dsidrmf) found" >&2
exit 1
