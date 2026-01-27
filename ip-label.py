#!/usr/bin/env python3

# Resolve client IPs to network labels in Apache access logs

import sys
import os
import glob
import ipaddress


def load_cidrs_from_script_dir():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    files = sorted(glob.glob(os.path.join(script_dir, "*.cidr")))

    nets = []
    for path in files:
        label = os.path.splitext(os.path.basename(path))[0]
        with open(path, "r", encoding="utf-8") as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                if "#" in line:
                    line = line.split("#", 1)[0].strip()
                    if not line:
                        continue
                try:
                    net = ipaddress.ip_network(line, strict=False)
                except ValueError:
                    continue
                nets.append((net, label))

    nets.sort(key=lambda x: x[0].prefixlen, reverse=True)
    return nets


def label_for_ip(ip_str, nets):
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return None

    for net, label in nets:
        if ip.version != net.version:
            continue
        if ip in net:
            return label
    return None


def write_line(s: str):
    sys.stdout.write(s)
    sys.stdout.flush()


def main():
    nets = load_cidrs_from_script_dir()

    for line in sys.stdin:
        if " " not in line:
            write_line(line)
            continue

        first, rest = line.split(" ", 1)
        lab = label_for_ip(first, nets)

        if lab is None:
            write_line(line)
        else:
            write_line(f"{lab} {rest}")


if __name__ == "__main__":
    main()
