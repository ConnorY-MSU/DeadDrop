#!/bin/bash
# provision-permissions.sh - locks down the two directories that hold
# key material on a deployed SecureLink device: ~/pki (the device's own
# cert + plain private key, if not using keyshare mode) and ~/keyshare
# (the keyshare-mode encrypted key + shares, per keyshare.h/tools/
# keyshare_setup.c). Run this once after copying key material onto a
# freshly provisioned Pi, or any time permissions need re-confirming
# (e.g. after Day 5's rotation drill deploys a new certificate).
#
# This was previously done ad hoc, by hand, during Week 4 Day 4's live
# testing (see TESTING.md) - this script folds that into a real,
# repeatable provisioning step instead of a one-off command.
#
# Usage: ./provision-permissions.sh
# (no arguments - operates on $HOME/pki and $HOME/keyshare, matching
# the fixed layout every Day 1-4 deployment step on both Pis used)

set -e

for dir in "$HOME/pki" "$HOME/keyshare"; do
    if [ -d "$dir" ]; then
        echo "Locking down $dir ..."
        # Directory itself: owner rwx only. Nobody else on the system
        # (other local users, if any existed) should even be able to
        # list what's in here.
        chmod 700 "$dir"

        # Every regular file inside: owner read/write only. Private
        # keys and key-shares must never be group/other-readable;
        # public certs (*_cert.pem, ca_cert.pem) don't strictly need
        # this, but there's no downside to holding the whole directory
        # to one consistent, simple rule rather than special-casing
        # "this file is public, that one isn't" and risking getting it
        # wrong on the next file added here.
        find "$dir" -maxdepth 1 -type f -exec chmod 600 {} \;

        echo "  $(ls -la "$dir" | tail -n +2 | wc -l) file(s) set to 600, directory set to 700"
    else
        echo "$dir does not exist - skipping (not an error; not every device uses both modes)"
    fi
done

echo "Done. Verify with: ls -la ~/pki ~/keyshare"
