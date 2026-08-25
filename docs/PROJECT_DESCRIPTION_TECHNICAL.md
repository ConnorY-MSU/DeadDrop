# DeadDrop: Technical Project Description

## Overview and Purpose

DeadDrop is a mutually authenticated, encrypted communication system built for two paired Raspberry Pi 5 devices to exchange messages over an untrusted network with no reliance on a third party message server. Each device is a self contained field terminal: a touchscreen, an ncurses based user interface, hardware status indicators, and a text to speech output for incoming messages. The two devices authenticate each other using mutual TLS with certificates issued by a private, purpose built certificate authority, and all traffic runs over a WireGuard based mesh network (Tailscale) rather than the open internet.

The project was built from first principles over a structured multi week effort. Cryptographic primitives were implemented and understood before any library code was trusted, the TLS and PKI layers were built and negative tested before the application protocol was layered on top, and the physical hardware and operating system hardening were treated as first class parts of the security posture, not an afterthought. This document describes the system as it stands with all planned hardening from the most recent security review completed, so a reviewer can evaluate the finished design rather than an intermediate state.

## Threat Model

The system is designed to resist the following categories of attacker, in order of the resources they realistically have available:

- An opportunistic attacker scanning the internet or a shared network for exposed services.
- A person with brief or extended physical access to one of the devices, including a lost or stolen unit.
- A technically capable individual attempting to intercept or tamper with traffic on a network either device is connected to.
- A moderately resourced, motivated attacker willing to spend real time and effort against the specific pair of devices.

The system does not claim resistance to a well funded, dedicated professional team or a nation state level adversary. Several structural choices described below (self hosted infrastructure, no formal protocol verification, no certified secure hardware module) are honest limits on what a small, unfunded project of this kind can realistically achieve, and those limits are stated plainly rather than implied away.

## System Architecture

The deployment consists of exactly two physical devices, referred to as Alpha and Bravo, each running a Raspberry Pi OS based image on a Raspberry Pi 5. Alpha runs the server role and Bravo runs the client role at the transport level, but the application protocol above that layer is fully symmetric: either device can send a message at any time, and both devices display and log incoming messages identically.

The two devices connect over a private WireGuard mesh (Tailscale), with a self hosted DERP relay used for the small minority of connections that cannot establish a direct peer to peer path. This removes reliance on a third party operator's relay infrastructure for the cases where direct connection is not possible, while keeping WireGuard's own mature, widely reviewed cryptography as the transport layer. The mesh network's own access control list is scoped so that only the two paired devices are permitted to reach each other's application port at all, independent of anything the application itself enforces.

On top of the mesh network, each device runs a custom application that performs a mutual TLS 1.3 handshake using wolfSSL before any application data is exchanged. Once the handshake succeeds, a symmetric session layer takes over: a dedicated receiver thread accepts incoming messages at any time, while the main thread accepts local input, so a message can arrive and be displayed while the local user is mid keystroke. All application layer messages are individually framed, HMAC authenticated, and carry a strictly increasing sequence number to prevent replay.

## Cryptographic Design

### Transport layer

TLS 1.3 is provided by wolfSSL, a mature and widely deployed open source TLS library, rather than any hand written transport cryptography. Certificate verification is mutual: the server requires and validates a client certificate before any application data is accepted, and the client does the same for the server. This is enforced structurally through wolfSSL's verification callback, not by an application level check that could be bypassed.

### Private certificate authority

A private certificate authority was generated specifically for this pair of devices and signs exactly two leaf certificates, one for each device. The certificate authority does not participate in any public trust chain and neither device trusts any certificate authority other than this one. Following the most recent hardening pass, the certificate authority's private key has been moved to offline storage rather than remaining on any network connected machine, so a compromise of the development workstation used to build and deploy the software no longer implies a compromise of the trust root. Because both certificates already exist and revocation is handled locally on each device, the certificate authority does not need to be online for the system to keep operating.

### Revocation

Each device maintains a local list of revoked certificate serial numbers, loaded at startup and checked inside the same TLS verification callback that performs chain validation. A certificate that is otherwise perfectly valid and signed by the trusted certificate authority is still rejected if its serial number appears on this list. This was verified with a live negative test: a genuinely valid, unexpired, correctly signed client certificate was rejected specifically because its serial number had been added to the revocation list, and the rejection reason logged by the server confirmed the revocation check, not a generic chain failure, was responsible.

### Message authentication and replay protection

Every application message is protected by an HMAC computed over the message header and body, using a key derived from the TLS session's own exported keying material rather than a separately negotiated secret. Each message also carries a sequence number that must strictly increase within a session, which the receiving side enforces before accepting the message. Both properties were fuzz tested extensively: over one million randomized and structurally mutated inputs were run against the message parser under AddressSanitizer and UndefinedBehaviorSanitizer with zero crashes or sanitizer reports.

### Hand implemented primitives

Early in the project, AES 128 and SHA 256 were implemented from published specifications as a foundational exercise, and both were verified against official test vectors. Neither implementation is used anywhere in the actual trust critical path of the deployed system. All cryptography that protects real data, including the TLS handshake itself, the message HMAC, and the disk encryption described below, uses wolfSSL or the operating system's own reviewed cryptographic libraries. This separation was a deliberate design decision made early and maintained throughout, specifically to avoid the well known risk of home written cryptography ending up load bearing.

## Key and Secret Management

### Device private keys and the mutual custody bootstrap

Rather than storing each device's private key as a plain file on its SD card, each device's key is split using a mutual custody scheme: each device holds one half of the other device's key material, and reconstructs its own working key at startup by fetching the other half from its paired device over the mesh network. This fetch is authenticated by checking the connecting peer's verified mesh network identity before releasing any key material, and the fetch listener starts before either device attempts to fetch from the other, so both devices coming online at unpredictable times, on different networks, will still converge without a hard dependency on boot ordering. The retry logic for this fetch has no timeout by design.

### Full disk encryption bound to device hardware

Each device's storage is encrypted with LUKS2, and the decryption key is derived from a secret held in the Raspberry Pi 5 system on chip's own one time programmable fuse memory, written once during provisioning and never stored anywhere else, including in any backup. This key exists only inside that specific physical chip and is read fresh from the fuses at every boot through the same firmware level mailbox interface the bootloader itself uses, then combined with the on disk LUKS header to unlock the root filesystem automatically, with no passphrase entry required at boot.

This design was verified empirically, not assumed. The initramfs level tooling that performs the unlock was extracted and run directly against a fresh copy of the image inside a chroot environment to confirm it worked before ever depending on it for a real boot. After provisioning, the encrypted card was physically removed and connected to a different Raspberry Pi running identical software: that second device derived a completely different key from its own, unburned fuses, and every attempt to unlock the card, including several deliberately incorrect guessed passphrases, was rejected outright. The card was then returned to its original device and confirmed to boot and unlock automatically across two independent cold boots. This demonstrates the intended property directly: a physically removed storage card is inert on any hardware other than the specific unit it was provisioned on.

### PIN lock

Each device supports a local PIN lock, independent of and never exposed to the network or cryptographic session layer. The PIN is never stored; instead, a memory hard key derivation function is applied to the PIN with a random per device salt, and only the resulting derived value is stored on disk. This replaced an earlier, weaker single round hashing approach specifically because a single hash round can be brute forced offline in a trivial amount of time if the hash file is ever extracted, while a properly tuned memory hard function resists that class of attack meaningfully. A short, increasing delay is also enforced between incorrect attempts through the live user interface, and that delay is persisted to disk so it survives a process restart, closing a gap where an attacker who could force the application to restart would otherwise reset the delay to zero.

## Application Security Features

### Emergency data destruction

Either device can trigger an irreversible wipe of all local chat history, saved messages, and received files, and the same wipe is propagated to the paired device automatically over the already authenticated session. The command requires an exact, case sensitive confirmation phrase to prevent an accidental trigger from a stray keystroke, and the wipe on the receiving device is trusted without additional confirmation specifically because the message arrived over an already mutually authenticated, replay protected session, meaning its mere valid arrival is itself proof it originated from the legitimate paired device.

### Network exposure scoping

The main application listener does not bind to all available network interfaces. It resolves and binds specifically to the device's mesh network address, and refuses to start at all if that address cannot be determined, rather than silently falling back to a broader, less scoped bind. This was a real gap found during review: the listener had originally bound to all interfaces, meaning the encrypted, authenticated application layer was still reachable from any network the device happened to be connected to, not only the intended mesh network. The fix was verified with a direct, physical cross device test: with a separate machine genuinely present on the same local network as the device, a connection attempt to the device's local network address was confirmed refused, while the identical connection attempt to its mesh network address succeeded, at the same moment, on the same network.

## Network Architecture

All device to device traffic runs over a private WireGuard based mesh network, using Tailscale's coordination plane with a self hosted DERP relay for cases where a direct peer to peer path cannot be established. The mesh network's own access control policy is scoped so that the two devices can reach only each other's application port, which means even if the application layer had a bug, an attacker without a valid mesh network identity has no path to the application at all.

Neither device performs unattended operating system package updates over an unreliable or public network, and the application's own WiFi setup screen deliberately uses only pre shared key authentication (open networks or a single shared password), not enterprise style username and certificate authentication, which is an explicitly acknowledged and documented limitation rather than an oversight.

## Operating System and Privilege Hardening

Both devices run their application as a dedicated, unprivileged system user under a hardened systemd service definition. The service's home directory access is restricted to read only except for the application's own data directory, and a substantial set of additional systemd sandboxing directives are applied, including restrictions on kernel tunables, kernel modules, control groups, the system clock, hostname changes, namespace creation, set user id and set group id execution, memory pages that are simultaneously writable and executable, and realtime scheduling.

A small number of aggressive sandboxing directives were deliberately not applied, each for a specific, documented reason tied to a genuine runtime dependency, such as the application's need to invoke a privilege elevation command for WiFi configuration and to access specific hardware device files for the touchscreen, display, and status indicators. These exclusions are recorded directly in the service definition files with the reasoning behind each one, so the decision is auditable rather than silent.

Privilege elevation available to the application's own operating system user is scoped to exactly the small set of commands the application actually invokes, rather than a broad, unscoped grant. This was verified by enumerating every command the application code actually shells out to, and confirming through the operating system's own privilege query tooling that the resulting rule resolves to exactly that set and nothing broader.

## Testing and Verification Methodology

Verification throughout this project favored direct, empirical confirmation over reading code and assuming correctness. Representative examples include:

- Reading raw hardware status register output to decode actual on screen colors byte by byte, rather than trusting the source code's own logic, which is how a genuine display bug was found and fixed.
- Running the message parser and the WiFi network name parser under AddressSanitizer and UndefinedBehaviorSanitizer against millions of randomized and structurally mutated inputs, including deliberately adversarial edge cases.
- Performing all four classic negative certificate tests, no client certificate presented, a certificate signed by an untrusted certificate authority, an expired certificate, and a revoked certificate, against the live running server, and confirming the specific rejection reason logged in each case matched the expected failure mode rather than a generic error.
- Physically pulling storage media and connecting it to different hardware to confirm an encryption property held, rather than trusting the encryption tooling's own success message.
- Static analysis across the full source tree using an independent tool, with every flagged item individually investigated rather than accepted or dismissed by default.

A full regression suite covering the cryptographic primitives, the message protocol, and the revocation logic is run after any change to code that could plausibly affect them, and the project maintains a complete, dated testing log recording verbatim results rather than a summary of outcomes.

## Known Limitations and Honest Scope

This project has not received a paid, professional security audit from an outside firm, and no amount of internal review fully substitutes for that. The application protocol layered on top of TLS, while carefully designed and fuzz tested, is bespoke and has not been through formal, adversarial cryptographic review. The system depends on Tailscale's coordination infrastructure for mesh network identity and access control even with a self hosted relay in place, which means a sufficiently capable attacker able to compromise or compel that infrastructure sits outside this project's control. There is no fully verified or cryptographically signed boot chain, meaning the disk encryption protects data at rest but does not by itself prevent a sufficiently determined attacker with extended physical access from tampering with the bootloader or kernel. No certified hardware security module or secure enclave is used; the disk encryption's hardware root of trust is the Raspberry Pi 5's own one time programmable fuse memory, which is a real and verified mechanism but not a certified security module in the formal sense. Message content is protected end to end, but connection metadata, meaning which device is talking to which and roughly when, remains visible to the mesh network's own infrastructure even with a self hosted relay.

These limitations are stated directly because an accurate account of what a system does and does not protect against is itself part of a credible security posture, and because every one of them reflects a genuine constraint of building and maintaining this system as a single developer rather than a funded team.

## Conclusion

DeadDrop demonstrates a complete, working, mutually authenticated encrypted communication system built from first principles, with real hardware backed key protection, a scoped and tested network exposure surface, a fuzz tested application protocol, and an explicit, honestly documented threat model and set of limitations. It is intended to meaningfully raise the cost and difficulty of casual, opportunistic, and moderately resourced attacks against the specific pair of devices it protects, while making no claim to withstand a professional, funded, or nation state level adversary. Feedback and review from computer science, information technology, and security professionals is welcomed and specifically invited, particularly on the application protocol layer described above, since that layer has not yet had the benefit of outside adversarial review.
