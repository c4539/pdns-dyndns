# DynDNS

A simple DynDNS tools for PowerDNS with MySQL / MariaDB backend (native zones).

## Update URL for FritzBOX

To properly update IPv4 and IPv6, I recommend calling the `update.php` twice (once per protocol). This can be achieved by specifying two URLs, separated by a space.

```
https://dyndns.example.net/update.php?usr=<username>&pwd=<pass>&domain=<domain>&ipaddr=<ipaddr> https://dyndns.example.net/update.php?usr=<username>&pwd=<pass>&domain=<domain>&ip6addr=<ip6addr>&ip6lanprefix=<ip6lanprefix>
```
