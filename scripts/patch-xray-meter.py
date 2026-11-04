#!/usr/bin/env python3
"""Patch only the reviewed dispatcher hooks in pinned Xray v26.10.31."""
from pathlib import Path
import shutil
import sys

root = Path(sys.argv[1])
file = root / "app/dispatcher/default.go"
text = file.read_text()


def replace(old, new):
    global text
    if text.count(old) != 1:
        raise SystemExit("Unexpected pinned Xray source; meter patch refused")
    text = text.replace(old, new, 1)


replace("\td.stats = sm\n", "\td.stats = sm\n\tif c, _ := sm.GetOrRegisterCounter(\"user>>>noway-meter>>>version\"); c != nil { c.Set(1) }\n")
replace("\t\tif p.Stats.UserOnline {\n\t\t\ttrackOnlineIP(ctx, d.stats", "\t\tnowayMeterLinks(ctx, d.stats, user.Email, inboundLink, outboundLink)\n\t\tif p.Stats.UserOnline {\n\t\t\ttrackOnlineIP(ctx, d.stats")
replace("\t\tif p.Stats.UserOnline {\n\t\t\ttrackOnlineIP(ctx, statsManager", "\t\tnowayMeterWrapped(ctx, statsManager, user.Email, link)\n\t\tif p.Stats.UserOnline {\n\t\t\ttrackOnlineIP(ctx, statsManager")
file.write_text(text)
shutil.copyfile(Path(__file__).resolve().parents[1] / "patches/xray/noway_meter.go", root / "app/dispatcher/noway_meter.go")
print("Applied NOWAY per-IP payload counters v1")
