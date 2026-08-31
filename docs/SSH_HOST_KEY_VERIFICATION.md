# SSH server identity verification

An SSH private key or password proves the **client** to the SSH server. It does not, by itself, prove that the server on the other end is the bastion you intended to reach.

OpenTable therefore verifies the server host key during SSH key exchange, before user authentication. If the key is not trusted, the tunnel is stopped before a database password, SSH password, private-key authentication attempt, or agent signature is sent.

## Trust source

OpenTable uses the same trust files as OpenSSH:

- `~/.ssh/known_hosts`
- `~/.ssh/known_hosts2` when present
- `/etc/ssh/ssh_known_hosts` and `/etc/ssh/ssh_known_hosts2` on Unix-like systems

The verifier understands:

- normal hostname entries
- OpenSSH hashed hostnames (`|1|...`)
- comma-separated patterns, `*` / `?` wildcards, and negated patterns
- `[hostname]:port` entries used for SSH ports other than 22
- multiple host-key algorithms for one server
- `@revoked` entries

A key mismatch is only labelled **changed** when the stored entry uses the same negotiated host-key algorithm. An RSA entry does not make a newly negotiated Ed25519 key look like a changed RSA key; it is simply untrusted until that Ed25519 key is pinned.

## First connection

OpenTable fails closed for a host that is not already trusted. The error includes the exact SHA256 fingerprint presented by the server.

Verify that fingerprint through a separate trusted channel, then connect once with OpenSSH so it can add the host to `known_hosts`, for example:

```bash
ssh ubuntu@bastion.example.com
```

or on a non-standard port:

```bash
ssh -p 2222 ubuntu@bastion.example.com
```

After the host is trusted, retry the OpenTable connection.

Do not blindly accept or replace a key only because a connection stopped working. A changed host key can be a legitimate server rebuild, but it can also indicate interception. Verify the new fingerprint before updating `known_hosts`.

## Host certificates

An ordinary directly pinned OpenSSH host-certificate blob can be compared like any other host key. `@cert-authority` entries are intentionally **not** treated as raw-key pins: validating an OpenSSH host certificate correctly requires checking the CA signature, principals, certificate validity and critical options. Until that validation exists, OpenTable fails closed rather than silently weakening the trust model.

## Why this lives below the UI

The check is attached directly to ssh2's `hostVerifier` during key exchange. It is not a warning banner or a renderer-side toggle, so every SSH tunnel path gets the same verification and no database connection is opened through an untrusted SSH peer.
