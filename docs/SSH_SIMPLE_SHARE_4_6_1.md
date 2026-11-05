# SSH sharing — 4.6.1

SSH sharing in the web panel and owner/admin bot presents two copy values:

1. `server:port@username:password`
2. A complete, single HTTP Upgrade payload using `/cdn-cgi`.

Direct defaults to port 80, which matches a plain raw HTTP payload client. The
backend also accepts direct port 443; enable TLS, certificate verification and
the endpoint hostname as SNI for that port. This custom credential string is
not a standardized URI; client parsing rules still apply.

The origin accepts `/cdn-cgi` and `/cdn-cgi/` while retaining `/ssh/raw` and
`/ssh/ws` for existing profiles. Authenticated provider aliases are
`/bunny/cdn-cgi` and `/cloudfront/cdn-cgi`. Existing origin-secret and viewer-IP
checks apply to both aliases. CloudFront's generated route guard must be
updated from the new setup export before using the new alias on an existing
distribution; the panel does not silently modify AWS resources.

CDN connections still require genuine RFC6455 binary WebSocket framing. A raw
HTTP string cannot supply framing after a handshake. The panel labels this
requirement when a CDN route is selected. Existing framed SSH adapter exports
remain available from the root CLI ZIP option.

Cloudflare reserves its own `/cdn-cgi/` endpoint. Adding an origin route does
not make that reserved namespace customizable on a Cloudflare-proxied domain.
Changing a URL path also cannot establish a mobile carrier's zero-rating
eligibility. Carrier access, TLS/SNI, CDN forwarding and an actual client data
transfer must be tested on the intended network. No external zero-rated host
or mobile network was available for this implementation's acceptance tests.

The mixed `GET … ACL …` example is not emitted. The existing strict single-
request parser and duplicate-header/body restrictions are retained.

## Passwords

New SSH accounts created through the web, bot or root CLI save their creation
password encrypted in `/etc/abdulbasit/ssh-share` (root only). This is separate
from public account metadata and list/status APIs. OpenSSL CMS uses AES-256-GCM
authenticated encryption and RSA-OAEP key wrapping. Passwords enter OpenSSL on
stdin, never as command arguments. Keep the private key and encrypted records
together in an owner-controlled backup; an Xray profile backup is not a backup
of this SSH vault.

Saved records are bound to the immutable account identity and current shadow
entry. An out-of-band OS password change invalidates the saved share password;
account deletion removes its encrypted record. Key loss is reported instead of
generating a replacement key over existing encrypted records.

Old password hashes cannot reveal their original passwords. An older account
needs its current password once, in the export dialog's registration field or
through this root CLI prompt:

```bash
abdulbasit-panelctl ssh-export USERNAME --save-password
```

The supplied password is verified locally using the OS's libcrypt before it
is saved. Later exports automatically use it. `--with-password` remains a
transient override; `--zip PATH` explicitly requests the existing full bundle.

## Apply the application update

```bash
cd /root/secure-vps-panel
git pull --ff-only origin main
bash scripts/update-ssh-compat.sh --sync-source
```

This updates the application, bot and Nginx routes with the updater's existing
recovery copy. It does not require rebuilding the native payload-meter cores.

Sources:
- https://developers.cloudflare.com/fundamentals/reference/cdn-cgi-endpoint/
- https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-working-with.websockets.html
- https://www.rfc-editor.org/rfc/rfc9112.html
- https://docs.openssl.org/3.0/man3/CMS_encrypt/
