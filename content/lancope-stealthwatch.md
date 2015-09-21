+++
title = "Lancope stealthwatch"
date = "2013-02-28"
publishdate = "2013-02-28"
categories = ["Security"]
tags = ["Lancope", "Netflow"]
slug = "lancope-stealthwatch"
project_url = "https://greyhat.dk/lancope-stealthwatch"
type = "post"
+++

Had a nice meeting yesterday with Cisco and some guys from Lanecope.
Must say that stealthwatch seems like a really great product. What their
product does is that is collects all flows (and more). Sums it up so you
can drill down via connections.

Basically it does something like this on your netflow data

```sh
    ~$ nfdump -R /var/cache/nfdump/data/asr0/nfcapd.201302281130:asr1/nfcapd.201302281133 -o long  'dst host 77.66.32.1'|head -10
    Date flow start          Duration Proto      Src IP Addr:Port          Dst IP Addr:Port   Flags Tos  Packets    Bytes Flows
    2013-02-28 11:29:58.616     0.000 TCP      198.89.107.36:41257 ->      77.66.32.1:80    ....S.   0        8      384     1
    2013-02-28 11:29:58.612     0.000 TCP       181.3.74.102:23628 ->      77.66.32.1:80    ....S.   0        8      384     1
    2013-02-28 11:29:58.612     0.000 TCP      122.149.174.9:25733 ->      77.66.32.1:80    ....S.   0        8      384     1
    2013-02-28 11:29:58.612     0.000 TCP     175.217.179.22:27301 ->      77.66.32.1:80    ....S.   0        8      384     1
    2013-02-28 11:29:58.613     0.000 TCP     141.149.190.34:56307 ->      77.66.32.1:80    ....S.   0        8      384     1
    2013-02-28 11:29:58.613     0.000 TCP       70.248.23.39:10543 ->      77.66.32.1:80    ....S.   0        8      384     1
    2013-02-28 11:29:58.613     0.000 TCP      96.45.178.104:62559 ->      77.66.32.1:80    ....S.   0        8      384     1
    2013-02-28 11:29:58.613     0.000 TCP      218.92.100.34:56154 ->      77.66.32.1:80    ....S.   0        8      384     1
    2013-02-28 11:29:58.613     0.000 TCP      59.37.156.114:34888 ->      77.66.32.1:80    ....S.   0        8      384     1
```

Stores it in a database for billing, security audits but also for
network analysis. The network analysis is based on policies and known
patterns (Beacons, traffic patterns/ports/flags, roundtrip etc). Then
lets you drill down on a specific hostgroup or target to see who, when
and that it talked to. It also integres ICE and logs from DHCP.

Based on this is can alert you if your are under DDOS or if someone just
just stole your files (Requires some configuration) or if some of your
hosts is part of a botnet. Really nice but properly also quite
expensive.
