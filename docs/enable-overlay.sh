#!/bin/bash
# enable-overlay.sh - Week 4 Day 5. Enables the root overlay filesystem
# via the `overlayroot` package (the same mechanism raspi-config's
# "Overlay File System" option uses - verified against
# /usr/bin/raspi-config's enable_overlayfs() function directly on this
# device, not assumed from generic docs).
#
# Uses `overlayroot=tmpfs:recurse=0` specifically, NOT plain
# `overlayroot=tmpfs` (raspi-config's own default): recurse=0 means
# ONLY "/" itself gets the RAM-backed overlay - every other mounted
# filesystem (critically, /boot/firmware and, via the loop mount on
# it, /persist and everything bind-mounted from it) stays real and
# writable. Per /etc/overlayroot.conf's own documentation: "if set to
# 0, only root will be set to read-only, and changes to other
# filesystems will be permanent." This is what makes the persistence
# setup in setup-persist-overlay.sh actually work - do NOT enable the
# overlay without recurse=0, or run this before that script, or the
# persisted paths may not behave as expected.
#
# DO NOT run this before:
#   1. Running setup-persist-overlay.sh
#   2. Rebooting and confirming (via `mount | grep persist`) that
#      /persist and all 5 bind mounts came up correctly
#   3. Confirming the app, Tailscale, and NetworkManager all still
#      work normally with persistence active but overlay still off
#
# This step is real, if manageable, risk: a mistake in the kernel
# command line could affect boot. It's a two-line, well-understood
# change (same technique the OS vendor's own raspi-config uses), and
# is reversible via SSH BEFORE rebooting (disable_overlayfs-equivalent:
# remove the "overlayroot=tmpfs:recurse=0 " prefix from cmdline.txt) -
# but once rebooted with a bad cmdline, recovery needs physical
# access. Watch the device's screen on this specific reboot.

set -e

if [ "$(id -u)" -ne 0 ]; then
    echo "Run with sudo." >&2
    exit 1
fi

CMDLINE=/boot/firmware/cmdline.txt

if grep -q "overlayroot=" "$CMDLINE"; then
    echo "overlayroot= is already present in $CMDLINE - not modifying:"
    grep -o "overlayroot=[^ ]*" "$CMDLINE"
    exit 0
fi

is_installed=$(dpkg -l overlayroot 2>/dev/null | grep -c '^ii' || true)
if [ "${is_installed:-0}" -eq 0 ]; then
    echo "Installing overlayroot package..."
    apt-get install -y overlayroot
fi

echo "Current cmdline.txt:"
cat "$CMDLINE"

sed -i "$CMDLINE" -e "s/^/overlayroot=tmpfs:recurse=0 /"

echo
echo "New cmdline.txt:"
cat "$CMDLINE"

echo
echo "Overlay filesystem will activate on the NEXT reboot."
echo "Reboot now with: sudo reboot"
echo "Watch the device's own screen through this reboot."
echo "After reboot, verify with: mount | grep ' / ' (should show overlay, not ext4)"
echo "                            mount | grep persist (should still show the 5 real mounts)"
