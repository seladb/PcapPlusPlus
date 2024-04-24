# Security Policy

<!--
## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| x.x.x   | :white_check_mark: |
| x.x.x   | :x:                |
-->

We encourage you to submit a pull request if you have a solution or fix. Your contributions help advance the library and enhance safety for all users :star:. We would very much appreciate any contribution to this project. If you're interested in contributing please visit the [contribution page](https://pcapplusplus.github.io/community#contribute) in PcapPlusPlus web-site.

## Reporting a Bug :bug: :bug:

Simply use GitHub issues to report a bug with related information to debug the issue :pencil:.

When filing your issue please make sure you provide a reproducible test case. Please also provide as much information about your environment as possible. We never know what information will be pertinent when trying narrow down the issue. Please include at least the following information:

- The version you're trying to run (a released version or the latest from master)
- Platform you're running on (MacOS, Linux, Windows, Android, FreeBSD + OS version)
- Architecture you're running on (32bit or 64bit)
- If working with libpcap, DPDK or PF_RING please specify the version you're using
- If working with DPDK, please make sure you can not reproduce the issue a clean DPDK version, meaning a version without PcapPlusPlus
- If you can provide a pcap file or anything else that will help us to reproduce the bug / verify the fix, please do so

If you already looked at the code and found the root cause - that's great :four_leaf_clover:! You can either create a GitHub pull request or point us to the exact place in the code where you think the bug is.

## Reporting a Vulnerability :closed_lock_with_key: :eyes:

To report a sensitive security issue :lock:, please email <pcapplusplus@gmail.com> with the following information:

- Description of the vulnerability
- Steps to reproduce the issue or a simple code piece
- Affected versions
- If applicable, a data sample (preferably `pcap/pcapng`) to reproduce
- If known, any mitigations or fixes for the issue

This project follows a 30-day disclosure timeline. Vulnerabilities will be listed in GitHub issues 30 days after the report is received, with the `vulnerability` tag :unlock:.
