#!/usr/bin/env python3
"""Stream-parse ISCXIDS2012 labeled flow XML into a compact CSV (memory-safe via iterparse).

Each <Testbed...Flows> record (identified by having a <Tag> child) becomes one CSV row with the
flow features and its label. A per-day "scenario" and derived "category" are added so detection can
be reported per attack type.

Usage:
  parse_iscx.py <out.csv> <xml_file>:<scenario>:<attack_name> [more ...]
Example:
  parse_iscx.py data/iscx_flows.csv \
     /tmp/iscx/.../TestbedTueJun15-1Flows.xml:TueJun15:DDoS_IRC_botnet \
     /tmp/iscx/.../TestbedThuJun17-3Flows.xml:ThuJun17:BruteForce_SSH
"""
import csv
import sys
from datetime import datetime
from xml.etree.ElementTree import iterparse

FIELDS = ["appName", "protocolName", "direction", "source", "destination",
          "sourcePort", "destinationPort", "totalSourceBytes", "totalDestinationBytes",
          "totalSourcePackets", "totalDestinationPackets", "startDateTime", "stopDateTime", "Tag"]
OUT_COLS = ["scenario", "appName", "protocolName", "direction",
            "sourcePort", "destinationPort", "totalSourceBytes", "totalDestinationBytes",
            "totalSourcePackets", "totalDestinationPackets", "duration_s", "tag", "category"]


def duration(start, stop):
    try:
        a = datetime.fromisoformat(start)
        b = datetime.fromisoformat(stop)
        return max(0, int((b - a).total_seconds()))
    except Exception:
        return 0


def parse_file(path, scenario, attack_name, writer):
    n = normal = attack = 0
    context = iterparse(path, events=("end",))
    for _, elem in context:
        # a flow record is any element that has a <Tag> child
        if elem.find("Tag") is None:
            continue
        g = {f: (elem.findtext(f) or "").strip() for f in FIELDS}
        tag = g["Tag"] or "Normal"
        is_attack = tag.lower() == "attack"
        category = attack_name if is_attack else "Normal"
        writer.writerow([
            scenario, g["appName"], g["protocolName"], g["direction"],
            g["sourcePort"] or 0, g["destinationPort"] or 0,
            g["totalSourceBytes"] or 0, g["totalDestinationBytes"] or 0,
            g["totalSourcePackets"] or 0, g["totalDestinationPackets"] or 0,
            duration(g["startDateTime"], g["stopDateTime"]),
            tag, category,
        ])
        n += 1
        normal += int(not is_attack)
        attack += int(is_attack)
        elem.clear()          # free the record
    print(f"[parse] {scenario}: {n} flows ({normal} normal, {attack} attack)")
    return n, normal, attack


def main():
    out = sys.argv[1]
    specs = sys.argv[2:]
    totals = [0, 0, 0]
    with open(out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(OUT_COLS)
        for spec in specs:
            path, scenario, attack = spec.split(":", 2)
            n, no, at = parse_file(path, scenario, attack, w)
            totals = [totals[0] + n, totals[1] + no, totals[2] + at]
    print(f"[parse] TOTAL: {totals[0]} flows, {totals[1]} normal, {totals[2]} attack -> {out}")


if __name__ == "__main__":
    main()
