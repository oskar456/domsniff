Simple passive DNS zone names collector
=======================================

``domsniff`` is a simple tool to record all positive DNS query results that
follow a regular expression. It can be used, for instance, to collect list of
registered domain names under a TLD that does not publish domain list.

Packet capturing generally requires root privileges. You can avoid it by
granting `cap_net_raw` capability to the Python interpreter binary:

      # setcap cap_net_raw=eip /path/to/python3.5
