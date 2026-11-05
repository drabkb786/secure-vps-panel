#!/usr/bin/env python3
"""Apply the small, reviewable NOWAY meter extension to pinned Dropbear 2026.94.

Upstream archive/license is unchanged; the resulting version is explicitly
labelled +noway-meter1. This is a modified build, not an official binary.
"""
from pathlib import Path
import sys

root = Path(sys.argv[1])


def replace(path, old, new):
    file = root / path
    text = file.read_text()
    if text.count(old) != 1:
        raise SystemExit("Unexpected pinned Dropbear source: " + path)
    file.write_text(text.replace(old, new, 1))


if (root / "src/noway-meter.c").exists():
    raise SystemExit("Source is already patched; start from the verified archive")
replace("src/sysoptions.h", '#define DROPBEAR_VERSION "2026.94"', '#define DROPBEAR_VERSION "2026.94+noway-meter1"')
replace("Makefile.in", "_CLISVROBJS=common-session.o", "_CLISVROBJS=noway-meter.o common-session.o")
for path in ("src/common-channel.c", "src/common-session.c", "src/svr-session.c"):
    replace(path, '#include "session.h"', '#include "session.h"\n#include "noway-meter.h"')
replace("src/common-channel.c", '\tint ret = DROPBEAR_SUCCESS;\n\tTRACE(("enter writechannel fd %d", fd))',
        '\tint ret = DROPBEAR_SUCCESS;\n\tunsigned int noway_before = channel->recvdonelen;\n\tTRACE(("enter writechannel fd %d", fd))')
replace("src/common-channel.c", '\t/* Window adjust handling */',
        '\tnoway_meter_count(channel->recvdonelen - noway_before, 0);\n\t/* Window adjust handling */')
replace("src/common-channel.c", '\tTRACE(("send_msg_channel_data: len %d fd %d", len, fd))',
        '\tnoway_meter_count(0, len);\n\tTRACE(("send_msg_channel_data: len %d fd %d", len, fd))')
replace("src/common-session.c", '\t\ttimeout.tv_sec = select_timeout();',
        '\t\tnoway_meter_tick(0);\n\t\ttimeout.tv_sec = select_timeout();\n\t\tif (IS_DROPBEAR_SERVER && ses.authstate.authdone && timeout.tv_sec > 1) timeout.tv_sec = 1;')
replace("src/svr-session.c", '\t/* Render the formatted exit message */',
        '\tnoway_meter_tick(1);\n\t/* Render the formatted exit message */')
(root / "src/noway-meter.h").write_text('''/* NOWAY meter extension, MIT license. */
void noway_meter_count(unsigned long long up, unsigned long long down);
void noway_meter_tick(int force);
''')
(root / "src/noway-meter.c").write_text(r'''/* NOWAY meter extension, MIT license. Counts accepted SSH channel payload.
 * Absolute per-process counters are checkpointed by a trusted local collector.
 * No network packet parsing, account credentials or claimed peer IPs are sent.
 */
#include "includes.h"
#include "session.h"
#include "noway-meter.h"
#include <sys/un.h>

static unsigned long long meter_up = 0, meter_down = 0;
static time_t meter_last = 0;
static int meter_fd = -1, meter_exiting = 0;
static pid_t meter_owner = 0;

void noway_meter_count(unsigned long long up, unsigned long long down) {
#if DROPBEAR_SERVER
    if (IS_DROPBEAR_SERVER && ses.authstate.authdone && (!meter_owner || meter_owner == getpid())) {
        meter_up += up; meter_down += down;
    }
#endif
}

void noway_meter_tick(int force) {
#if DROPBEAR_SERVER
    struct sockaddr_un address;
    struct timeval timeout;
    char message[128], reply[8];
    int length, fresh = 0;
    ssize_t result;
    time_t current;
    if (!IS_DROPBEAR_SERVER || !ses.authstate.authdone || meter_exiting) return;
    if (meter_owner && meter_owner != getpid()) {
        if (meter_fd >= 0) close(meter_fd);
        meter_fd = -1; meter_exiting = 1; return;
    }
    meter_owner = getpid();
    current = time(NULL);
    if (!force && current == meter_last) return;
    meter_last = current;
    if (meter_fd < 0) {
        meter_fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (meter_fd < 0) return;
        fcntl(meter_fd, F_SETFD, FD_CLOEXEC);
        memset(&address, 0, sizeof(address));
        address.sun_family = AF_UNIX;
        strcpy(address.sun_path, "/run/abdulbasit-meter/ssh.sock");
        timeout.tv_sec = 1; timeout.tv_usec = 0;
        setsockopt(meter_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        setsockopt(meter_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        if (connect(meter_fd, (struct sockaddr*)&address, sizeof(address)) < 0) goto disconnected;
        fresh = 1;
    }
    length = snprintf(message, sizeof(message), "M %llu %llu\n", meter_up, meter_down);
    result = send(meter_fd, message, length, MSG_NOSIGNAL);
    if (result != length) goto disconnected;
    if (fresh) {
        result = recv(meter_fd, reply, sizeof(reply), 0);
        if (result == 5 && memcmp(reply, "DENY\n", 5) == 0) {
            meter_exiting = 1;
            dropbear_exit("Account IP/data policy denied this session");
        }
        if (result != 3 || memcmp(reply, "OK\n", 3) != 0) goto disconnected;
        timeout.tv_sec = 0; timeout.tv_usec = 20000;
        setsockopt(meter_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    }
    return;
disconnected:
    close(meter_fd); meter_fd = -1;
#endif
}
''')
print("Applied NOWAY authenticated channel meter v1")
