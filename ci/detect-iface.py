#!/usr/bin/env python3
from scapy.all import conf


def main():
    print(conf.iface.name)


if __name__ == "__main__":
    main()
