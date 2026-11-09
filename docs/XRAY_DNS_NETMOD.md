# Xray-over-DNSTT (NetMod) — resolver and browsing checklist

The public-facing DNS resolver (**8.8.8.8:53**) is not the DNSTT
**authoritative nameserver**. For example, an NS record for
`xdns.arm-29.tech` must delegate to a DNS-only nameserver such as
`ns1.arm-29.tech`, whose A/AAAA points directly to the VPS. Using Google's
recursive DNS does **not** replace that delegation or public UDP/53.

## Update an existing VPS

Updating the GitHub repository does not overwrite persistent network settings.
After installing/updating the panel on the VPS, explicitly set the server-side
Xray resolver values if you want Google's resolvers:

```sh
sudo abdulbasit-panelctl dns-set --server 8.8.8.8 --server 8.8.4.4 --strategy UseIPv4
sudo abdulbasit-panelctl slowdns-status
sudo abdulbasit-panelctl slowdns-check
sudo systemctl status abdulbasit-xray abdulbasit-dnstt --no-pager
sudo ss -lunp | grep -E '(:53\\b|:5353[01]\\b)'
sudo ss -ltnp | grep ':10006'
```

The private VLESS listener is `127.0.0.1:10006`; only DNSTT may expose
its traffic via the delegated DNS zone. Never expose port 10006 publicly.

## NetMod client setup

1. In **DNS tunnels**, enable `Xray` or `SSH + Xray`. When using both,
   use distinct non-overlapping delegated DNS zones.
2. In **Xray DNS**, create a new VLESS-only account or select an eligible
   existing VLESS account. Its IP cap must be **0** and blocked IP list empty.
3. Select **DNS link / ZIP** and download **NetMod DNS setup**. Keep the
   VLESS account UUID/private export secure.
4. Set the client DNS resolver to `8.8.8.8:53` for UDP mode. Supply the
   exported **Xray** tunnel zone and the **public** DNSTT key.
5. Start DNSTT, listening locally on the *device* at `127.0.0.1:7001`.
   Only then import the VLESS TCP link to `127.0.0.1:7001`.
   A VLESS import link alone never starts DNSTT.
6. Enable the device's VPN/tunnel mode including DNS traffic. The exported
   standalone Xray JSON includes `8.8.8.8` and `8.8.4.4` resolvers.
7. Test a hostname and an IP **through the actual client connection**, not
   merely a "connected" label. A working local service only proves that
   listeners are up — it does not prove Jazz or any mobile operator passes
   recursive DNS tunnel traffic.

NetMod offers both DNSTT and VLESS, but client builds may not support
composing them in one profile. If the DNSTT mode only supports SSH,
use a separate official DNSTT client to create port 7001 and an Xray
client configured to use that local VLESS target. Avoid advertising a
one-tap standalone VLESS DNS link unless that combination was tested.

## Troubleshooting when connected but websites do not load

- **No DNS delegation**: run `slowdns-check` and fix NS delegation to the
  VPS; this cannot be repaired by changing the resolver IP.
- **No port 53 UDP**: check VPS security-group/UFW rules, provider filtering,
  conflicts, and the actual server DNSTT listener.
- **DNSTT cannot exchange payloads**: use the exported DoH / DoT commands
  where the client supports them; try a smaller DNSTT MTU (e.g. 900) only
  after confirming baseline behavior and saving the current setting.
- **VLESS local socket closed**: the DNSTT process must bind `7001` and
  the managed Xray process must bind `10006` on the server.
- **Connected but no domain resolution**: check VPN DNS routing and request
  a client-side log; a local/loopback source IP like `127.0.0.1` does not
  show the mobile viewer IP.
- **IP works, HTTPS does not**: check DNS responses and app TUN routing.
  A carrier package may not allow the full DNS tunnel payload stream.
- **Server-side Xray resolver still 1.1.1.1**: persistent settings override
  the code default; use the `dns-set` CLI command above.

No source change can guarantee this tunnel works on a specific mobile
package without a real over-the-air connectivity/browsing test.
