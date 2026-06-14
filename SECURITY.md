# Security Policy

Quipu-Log stores audit logs — records whose value is that they can be trusted
after the fact. A vulnerability here is not just a bug; it can mean a tamper
that the chain was supposed to make evident goes unnoticed. We take reports
seriously and ask you to report privately first.

## Reporting a vulnerability

**Do not open a public issue for a security report.** Instead, use GitHub's
private vulnerability reporting on this repository:

> Security → Report a vulnerability
> (`https://github.com/quipu-log/Quipu-Log/security/advisories/new`)

If that is unavailable to you, open a minimal public issue that says only "I
have a security report, please open a private channel" — with no details — and
we will follow up.

Please include, as far as you can: the affected crate and version (or commit),
the conditions needed to trigger it, the impact (what an attacker gains), and a
proof of concept if you have one.

### What to expect

- **Acknowledgement** within 3 business days.
- **An initial assessment** (severity, affected versions) within 10 business
  days.
- **Coordinated disclosure**: we will agree on a timeline with you, fix in
  private, release a patched version, and credit you in the advisory unless you
  prefer otherwise.

## Supported versions

Quipu-Log is pre-1.0. Security fixes land on the latest released version; there
is no back-porting to older 0.x lines yet. Pin a version and watch releases.

| Version | Supported |
|---|---|
| latest `0.x` | ✅ |
| older `0.x`  | ❌ |

## Scope and threat model

What the project defends, and where it deliberately draws the line, is part of
the design — reports are most useful when they target the actual model:

- **Tamper-evidence, not tamper-prevention.** Per-table hash chains and signed
  checkpoints make in-place edits and removed/replaced segments *detectable*
  after the fact; they do not stop a disk-level actor from altering files. A
  report that "an attacker with write access to the store changed a record" is
  in scope only if the change is **not** caught by `verify_integrity` /
  checkpoint verification.
- **Single-writer by design.** The store is one process behind a file lock.
  Availability of that process is solved at the client (`quipu-client`), not by
  replication; "the daemon is a single point of availability" is a documented
  scope decision, not a vulnerability.
- **Server key boundary.** `quipu-server` needs only the HMAC key and the RSA
  *public* key to append and hash-search. Running it without the private key is
  the intended hardened mode (encrypted fields come back as ciphertext for the
  client to decrypt). A path by which a public-key-only server recovers
  plaintext **is** a vulnerability.
- **Confidentiality of protected fields.** SHA-256 fields are searchable and
  brute-forceable for low-entropy values *by design* (documented on
  `FieldProtection::Sha256`); HMAC and RSA fields are the confidential options.
  A report should account for which protection was chosen.
- **Transport.** TLS termination is in-process and in scope. Plaintext HTTP is
  offered only for deployments behind a trusted TLS-terminating proxy and is
  documented as such.

Out of scope: denial of service from an authenticated admin token, physical
access to key files, and weaknesses in dependencies already tracked by their
own advisories (report those upstream, and tell us so we can bump).

## Known dependency advisories

- **RUSTSEC-2023-0071** — the `rsa` crate (used for `Rsa` field protection) is
  subject to the Marvin timing side-channel, a potential key-recovery attack;
  no fixed release exists upstream yet. The side-channel is only reachable
  where the RSA *private* key actually decrypts — a client or a full server,
  never the hardened public-key-only (write-only) server, which holds no
  private key. Mitigate by keeping RSA decryption off attacker-observable
  timing oracles and using `Hmac` for fields that only need search. We will
  bump as soon as upstream ships a fix.
