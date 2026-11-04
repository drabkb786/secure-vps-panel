# NOWAY 4.2 stability audit

## Reproduced defects and fixes

- The exported WSS-to-SSH adapter held its protocol lock while blocking on TLS
  writes from a second thread. Simultaneous upload/download could stall. TLS and
  WebSocket state now have one asyncio owner; stdin/stdout use bounded queues,
  partial writes are completed, and control replies do not wait for upload drain.
- Read-only daemon commands previously authorized while holding the mutation
  lock. A running Certbot command could block status and browser session checks.
  Read-only authorization now uses the atomic credential files outside that lock;
  state-changing commands still serialize authorization with execution.
- Package replacement unlinks an executable still mapped by active SSH sessions.
  Accounting now verifies the kernel-held `/proc/PID/exe` inode, including the
  deleted suffix, instead of requiring its old pathname to exist. Executable
  allowlists, root ownership, safe mode, cgroup ancestry and PID-reuse checks remain.
- Unlimited-IP accounts no longer trigger socket/FD scans. Empty session sets
  also skip kernel socket inspection. Finite IP limits retain their existing checks.
- Independent CDN health/upgrade probes run in a bounded pool, so one check
  waits for the slowest route rather than adding five network timeouts together.
  The combined report is still saved under serialized command execution.
- REALITY backup flags reject non-booleans; export warnings and diagnostic hints
  identify the selected CDN and SSH backend accurately.

## Dependency maintenance

`wsproto` moves from 1.2.0 to 1.3.2 with `h11` 0.16.0. Ordinary installations
install SHA-256 verified official pure-Python wheels into a versioned private
vendor directory, atomically activated after extraction. Ubuntu Python packages
are not overwritten. MIT license files remain included. Private runtime builds
and exported adapter instructions use the same versions.

Official checksum sources:
- https://pypi.org/project/wsproto/1.3.2/
- https://pypi.org/project/h11/0.16.0/

Nginx, Python, OpenSSL LTS, Certbot, Fail2ban and Xray retain the already verified
4.1 pins. A distribution version string alone is not evidence of missing security
patches. Optional private runtime activation remains separately reversible.

## Verification and limits

The regression suite transfers and byte-compares an 8 MiB random payload through
real TLS with constrained TCP buffers, concurrent WebSocket pings and SSH-style
pipes. It covers remote closure while stdin remains open, writer-first RPC
concurrency, partial pipe writes, deleted executable accounting and failed
dependency downloads preserving the prior activation. The old adapter stalled in
the same local pressure harness; the new one completed. This is a local regression
result, not a claim about WAN bandwidth, mobile networks, CDN routes or latency.

GitHub CI also exercises actual Nginx, Xray, OpenSSH, Dropbear, DNS tunnelling,
client formats and private-runtime rollback. Run real client transfers after
installing on the VPS; this repository change does not deploy to the live server.
Previously exported WSS adapter files must be downloaded again to receive the fix.
