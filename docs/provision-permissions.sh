#!/bin/bash
# provision-permissions.sh - locks down the directories that hold key
# material and local chat state on a deployed SecureLink device: ~/pki
# (the device's own cert + plain private key, if not using keyshare
# mode), ~/keyshare (the keyshare-mode encrypted key + shares, per
# keyshare.h/tools/keyshare_setup.c), and ~/.securelink (the PIN hash,
# the persisted message log, and received files - see lock.h/msglog.h/
# session.c). Run this once after copying key material onto a freshly
# provisioned Pi, or any time permissions need re-confirming (e.g.
# after Day 5's rotation drill deploys a new certificate).
#
# This was previously done ad hoc, by hand, during Week 4 Day 4's live
# testing (see TESTING.md) - this script folds that into a real,
# repeatable provisioning step instead of a one-off command.
#
# REAL BUG THIS SCRIPT NOW ALSO CATCHES, found via live testing: an
# earlier debugging session had run this app via `sudo openvt` (see
# TESTING.md's touch-input testing narrative), which created
# ~/.securelink as ROOT-owned before it ever existed under the real
# systemd service's own `User=connor`. Once created, the real service
# (running as connor, never root) silently lost the ability to write
# INTO that directory at all - msglog_append()'s and the received-file
# save's own "best-effort, don't interrupt a real message exchange
# over a persistence failure" design meant this failed completely
# silently for msglog, and produced a real but easy-to-miss history
# notice ("(failed to save received file ...)") for file transfers -
# neither ever surfaced as an obvious crash. `chown` (not just chmod)
# is included below specifically because of this - a permissions-only
# fix would not have corrected a wrong OWNER.
#
# Usage: ./provision-permissions.sh
# (no arguments - operates on $HOME/pki, $HOME/keyshare, and
# $HOME/.securelink, matching the fixed layout every Day 1-4/session
# deployment step on both Pis used)

set -e

for dir in "$HOME/pki" "$HOME/keyshare" "$HOME/.securelink"; do
    if [ -d "$dir" ]; then
        echo "Locking down $dir ..."
        # Ownership first - see the REAL BUG note above for exactly why
        # this can't be skipped in favor of chmod alone.
        chown -R "$(id -un):$(id -gn)" "$dir"

        # Directory itself (and any subdirectory, e.g. .securelink's
        # own received/ - see session.c): owner rwx only. Nobody else
        # on the system (other local users, if any existed) should
        # even be able to list what's in here.
        chmod 700 "$dir"
        find "$dir" -mindepth 1 -type d -exec chmod 700 {} \;

        # Every regular file, at any depth: owner read/write only.
        # Private keys, key-shares, the PIN hash, the message log, and
        # received files must never be group/other-readable; public
        # certs (*_cert.pem, ca_cert.pem) don't strictly need this, but
        # there's no downside to holding the whole tree to one
        # consistent, simple rule rather than special-casing "this file
        # is public, that one isn't" and risking getting it wrong on
        # the next file added here.
        find "$dir" -type f -exec chmod 600 {} \;

        echo "  $(find "$dir" -type f | wc -l) file(s) set to 600, directories set to 700, ownership set to $(id -un):$(id -gn)"
    else
        echo "$dir does not exist - skipping (not an error; not every device uses both key modes, and ~/.securelink is created on first use)"
    fi
done

echo "Done. Verify with: ls -la ~/pki ~/keyshare ~/.securelink"
