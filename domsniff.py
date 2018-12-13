#!/usr/bin/env python3
# vim: ts=4 expandtab

import re

import click
import pcap
import dpkt

domainset = set()


def readset(filename):
    global domainfile
    try:
        with open(filename, 'r') as f:
            for line in f:
                domainset.add(line.strip())
    except IOError:
        pass
    domainfile = open(filename, 'a')


def register_name(domainre, name):
    m = domainre.search(name.lower())
    if m and m.group(0) not in domainset:
        d = m.group(0)
        domainset.add(d)
        print(d, file=domainfile, flush=True)
        print(d, flush=True)


@click.command()
@click.option(
    "--interface", "-i",
    show_default=True,
    default="any",
)
@click.option(
    "--regexp", "-r",
    help="Regular expression to match",
    show_default=True,
    default=r"[-0-9a-zA-Z]+\.cz$",
)
@click.argument("domainlist")
def main(domainlist, interface, regexp):
    """
    Capture positive DNS answers on an interface.
    Collect unique domain names following the regular expression to a text
    file, one record per line.
    """
    readset(domainlist)
    domainre = re.compile(regexp)
    pc = pcap.pcap(name=interface, promisc=False)
    pc.setfilter("udp src port 53")
    if interface == "any":
        frame = dpkt.sll.SLL()  # Linux cooked frame
    else:
        frame = dpkt.ethernet.Ethernet()
    dnsmessage = dpkt.dns.DNS()
    for ts, pkt in pc:
        frame.unpack(pkt)
        try:
            dnsmessage.unpack(frame.data.data.data)
            if dnsmessage.rcode == dpkt.dns.DNS_RCODE_NOERR and \
               dnsmessage.an:
                register_name(domainre, dnsmessage.an[0].name)
        except (KeyboardInterrupt, IOError):
            raise
        except (ValueError, IndexError, dpkt.UnpackError):
            pass


if __name__ == '__main__':
    main()
