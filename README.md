# High Abuse Surface

You find known risky networks in this repo and a Pythons script that replaces client IPs with network names.

## Usage

```shell
tail -f /var/log/apache2/*access.log | high-abuse-surface/ip-label.py
```
