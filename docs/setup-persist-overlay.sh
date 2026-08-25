#!/bin/bash
# setup-persist-overlay.sh - Week 4 Day 5. Sets up a small, real
# (non-overlay) filesystem for the handful of paths that must survive
# a reboot once the root overlay filesystem is enabled, and bind-mounts
# each of them into place. Run this BEFORE enabling the overlay itself
# (see docs/enable-overlay.sh) - this script is safe on its own (worst
# case a mount unit fails with `nofail` and the system boots normally
# with the original, non-persistent directory); the overlay step is
# the one that actually removes the safety net of "just reboot to
# undo," so proving persistence plumbing works FIRST, without overlay
# in the mix yet, catches ordering/typo bugs cheaply.
#
# THE MECHANISM (verified against this device's actual overlayroot
# package - /etc/overlayroot.conf's own comments, not assumed):
# overlayroot's `recurse` parameter controls whether OTHER mounted
# filesystems also get swept into the RAM-backed overlay, or only "/"
# itself. This project uses recurse=0 (see enable-overlay.sh) so any
# separately-mounted filesystem stays real and writable. /boot/firmware
# is one such separate filesystem (its own partition, never part of
# root's own overlay) - so a persistent ext4 image FILE stored there,
# loop-mounted at /persist, is itself unaffected by the root overlay
# regardless of recurse, and everything bind-mounted from it inherits
# that same real, persistent behavior.
#
# Paths persisted (see Week 4 Build Log's Day 5 section for why each
# one is on this list):
#   /var/lib/tailscale                     - Tailscale node auth state
#   $HOME/.deaddrop                      - PIN salt+hash
#   /etc/NetworkManager/system-connections - WiFi profiles joined via
#                                             the Days 2-3 UI (nmcli)
#   $HOME/pki                              - this device's cert/key
#                                             (also holds
#                                             revoked_serials.txt -
#                                             moved there so cert
#                                             rotation's revocation-
#                                             list update persists too)
#   $HOME/keyshare                         - the keyshare-mode
#                                             encrypted key + shares
#
# Idempotent: safe to re-run (checks before creating/appending).

set -e

PERSIST_IMG="/boot/firmware/persist.img"
PERSIST_MNT="/persist"
PERSIST_SIZE_MB=96

if [ "$(id -u)" -ne 0 ]; then
    echo "Run with sudo." >&2
    exit 1
fi

REAL_HOME=$(getent passwd "${SUDO_USER:-connor}" | cut -d: -f6)
if [ -z "$REAL_HOME" ]; then
    echo "Could not resolve the invoking user's home directory - aborting." >&2
    exit 1
fi
echo "Provisioning persistence for user home: $REAL_HOME"

# --- Step 1: create the persist image, if it doesn't already exist ---
if [ ! -f "$PERSIST_IMG" ]; then
    echo "Creating $PERSIST_SIZE_MB MB persist image at $PERSIST_IMG ..."
    dd if=/dev/zero of="$PERSIST_IMG" bs=1M count="$PERSIST_SIZE_MB" status=none
    mkfs.ext4 -q -F "$PERSIST_IMG"
else
    echo "$PERSIST_IMG already exists - not recreating (would destroy existing persisted data)."
fi

mkdir -p "$PERSIST_MNT"

# --- Step 2: mount it now (temporarily, for migration) if not already mounted ---
if ! mountpoint -q "$PERSIST_MNT"; then
    mount -o loop "$PERSIST_IMG" "$PERSIST_MNT"
    echo "Mounted $PERSIST_IMG at $PERSIST_MNT"
fi

# --- Step 3: create subdirectories and migrate any existing real content in ---
declare -A PATHS=(
    [var-lib-tailscale]="/var/lib/tailscale"
    [dot-deaddrop]="$REAL_HOME/.deaddrop"
    [nm-system-connections]="/etc/NetworkManager/system-connections"
    [pki]="$REAL_HOME/pki"
    [keyshare]="$REAL_HOME/keyshare"
)

for name in "${!PATHS[@]}"; do
    target="${PATHS[$name]}"
    persist_sub="$PERSIST_MNT/$name"

    mkdir -p "$persist_sub"

    # Only migrate in if the persist copy is still empty (first run) -
    # never overwrite already-persisted data on a re-run.
    if [ -z "$(ls -A "$persist_sub" 2>/dev/null)" ] && [ -d "$target" ] && [ -n "$(ls -A "$target" 2>/dev/null)" ]; then
        echo "Migrating existing $target -> $persist_sub"
        rsync -a "$target"/ "$persist_sub"/
    fi

    # Preserve ownership matching the ORIGINAL target directory (root
    # for /var/lib/tailscale and /etc/NetworkManager/system-connections,
    # the real user for the rest) so the bind mount doesn't silently
    # change who owns these paths.
    if [ -d "$target" ]; then
        owner=$(stat -c '%U:%G' "$target")
        chown -R "$owner" "$persist_sub"
    fi
done

# Special case: move revoked_serials.txt into the pki persist copy too,
# if it exists in its old location and hasn't been moved yet - see the
# header comment above for why it lives here now.
OLD_REVOKED="$REAL_HOME/deaddrop/revoked_serials.txt"
NEW_REVOKED="$PERSIST_MNT/pki/revoked_serials.txt"
if [ -f "$OLD_REVOKED" ] && [ ! -f "$NEW_REVOKED" ]; then
    echo "Moving revoked_serials.txt into the persisted pki/ directory"
    cp "$OLD_REVOKED" "$NEW_REVOKED"
    chown "${SUDO_USER:-connor}:${SUDO_USER:-connor}" "$NEW_REVOKED"
fi

# --- Step 4: fstab entries, only added if not already present ---
FSTAB=/etc/fstab
add_fstab_line() {
    local line="$1"
    if ! grep -qF "$line" "$FSTAB"; then
        echo "$line" >> "$FSTAB"
        echo "Added to fstab: $line"
    else
        echo "Already in fstab: $line"
    fi
}

add_fstab_line "$PERSIST_IMG  $PERSIST_MNT  ext4  loop,defaults,nofail  0  2"
add_fstab_line "$PERSIST_MNT/var-lib-tailscale  /var/lib/tailscale  none  bind,nofail  0  0"
add_fstab_line "$PERSIST_MNT/dot-deaddrop  $REAL_HOME/.deaddrop  none  bind,nofail  0  0"

# REAL INCIDENT (Day 5 live testing on both Pis): without the two
# x-systemd.* options below, this bind mount has no ordering guarantee
# relative to NetworkManager.service, which starts very early in boot.
# NetworkManager occasionally won the race, read a half-mounted (still
# showing the original, real) system-connections directory, and then
# the bind mount landed underneath it mid-startup - NetworkManager
# crash-looped ("Start request repeated too quickly") and both devices
# lost network entirely (~20+ minutes of total unreachability, real
# physical power cycles required to recover). x-systemd.requires-
# mounts-for forces /persist itself to be ready first; x-systemd.before
# forces this specific bind mount to complete before NetworkManager.
# service is allowed to start at all. Verified via two isolated,
# full reboots after the fix - both clean on the first attempt.
add_fstab_line "$PERSIST_MNT/nm-system-connections  /etc/NetworkManager/system-connections  none  bind,nofail,x-systemd.requires-mounts-for=$PERSIST_MNT,x-systemd.before=NetworkManager.service  0  0"
add_fstab_line "$PERSIST_MNT/pki  $REAL_HOME/pki  none  bind,nofail  0  0"
add_fstab_line "$PERSIST_MNT/keyshare  $REAL_HOME/keyshare  none  bind,nofail  0  0"

echo
echo "Done. NOT yet active as bind mounts on the live filesystem - reboot to"
echo "activate all fstab entries (loop mount + 5 bind mounts) via systemd's"
echo "normal fstab processing, then verify with: mount | grep persist"
echo
echo "Overlay filesystem has NOT been touched by this script - that is a"
echo "separate, deliberate step (see docs/enable-overlay.sh), run only"
echo "after confirming the above survives a reboot cleanly on its own."
