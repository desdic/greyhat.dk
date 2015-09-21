+++
title ="DNS amplification by example"
description = "DNS amplification by example"
date = "2013-04-22"
publishdate ="2013-04-22"
categories =["security"]
tags =["DDOS", "DNS", "GCC", "Linux"]
slug = "dns-amplification-by-example"
project_url = "https://greyhat.dk/dns-amplification-by-example"
type = "post"
+++

How it works
============

DNS amplification is very easy to make and quite effective. An attacker
finds a DNS resolver that is public, creates a spoofed UDP DNS request
originating from the targets address sending the DNS response to the
target. The trick in this attack is to create a bigger output then input
(hence the amplification). What better way than to request a list of
authority records for a top level like .com

```sh
    # dig soa com @localhost

    ; <<>> DiG 9.7.3 <<>> soa com @localhost
    ;; global options: +cmd
    ;; Got answer:
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 60774
    ;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 13, ADDITIONAL: 0

    ;; QUESTION SECTION:
    ;com.               IN  SOA

    ;; ANSWER SECTION:
    com.            837 IN  SOA a.gtld-servers.net. nstld.verisign-grs.com. 1366568135 1800 900 604800 86400

    ;; AUTHORITY SECTION:
    com.            92359   IN  NS  b.gtld-servers.net.
    com.            92359   IN  NS  m.gtld-servers.net.
    com.            92359   IN  NS  l.gtld-servers.net.
    com.            92359   IN  NS  f.gtld-servers.net.
    com.            92359   IN  NS  c.gtld-servers.net.
    com.            92359   IN  NS  d.gtld-servers.net.
    com.            92359   IN  NS  g.gtld-servers.net.
    com.            92359   IN  NS  e.gtld-servers.net.
    com.            92359   IN  NS  k.gtld-servers.net.
    com.            92359   IN  NS  h.gtld-servers.net.
    com.            92359   IN  NS  j.gtld-servers.net.
    com.            92359   IN  NS  a.gtld-servers.net.
    com.            92359   IN  NS  i.gtld-servers.net.

    ;; Query time: 23 msec
    ;; SERVER: ::1#53(::1)
    ;; WHEN: Sun Apr 21 20:17:01 2013
    ;; MSG SIZE  rcvd: 300
```

Looking at this using tcpdump it gets quite clear that the request is
quite smaller than the response

```sh
    20:17:01.146195 IP6 (hlim 64, next-header UDP (17) payload length: 29) ::1.43296 > ::1.53: [udp sum ok] 60774+ SOA? com. (21)
    20:17:01.168318 IP6 (hlim 64, next-header UDP (17) payload length: 308) ::1.53 > ::1.43296: [udp sum ok] 60774 q: SOA? com. 1/13/0 com. SOA a.gtld-servers.net. nstld.verisign-grs.com. 1366568135 1800 900 604800 86400 ns: com. NS b.gtld-servers.net., com. NS m.gtld-servers.net., com. NS l.gtld-servers.net., com. NS f.gtld-servers.net., com. NS c.gtld-servers.net., com. NS d.gtld-servers.net., com. NS g.gtld-servers.net., com. NS e.gtld-servers.net., com. NS k.gtld-servers.net., com. NS h.gtld-servers.net., com. NS j.gtld-servers.net., com. NS a.gtld-servers.net., com. NS i.gtld-servers.net. (300)
```

The request in this case is 21 bytes and the response is 300 bytes (That
is almost 15 times bigger) and this is without DNSSEC (DNSSEC has a much
bigger response). All these requests will of course be dropped by the
target machine but making enough of these will simply flood the
bandwidth of the server/router (Or even ISP) with very little effort.

Behind the scene
================

Now there is plenty of tools out for spoofing packages or one could
simply rent a botnet. But I'm a strong believer in knowing how is the
key to prevent it so lets examine how to create a spoofed UDP DNS
request using gcc and Linux.

The systemcall sendto(2) is used for sending data but when combined with
raw sockets you get to customise the OSI layers ([IP header](http://en.wikipedia.org/wiki/IPv4_header#Header "IP header" and [UDP header](http://en.wikipedia.org/wiki/User_Datagram_Protocol "UDP header").

I have provided an example on how to create a spoofed DNS request but
the interesting parts are really

```c
            packet.ip.ip_dst.s_addr = inet_addr("192.168.1.1");
            packet.ip.ip_src.s_addr = inet_addr("192.168.1.7");
```

and

```c
            remote_addr.sin_addr.s_addr = packet.ip.ip_dst.s_addr;
            remote_addr.sin_port = packet.udp.uh_dport;
            remote_addr.sin_family = AF_INET;
```

The rest is just basic networking code using C.

[dns_amplification.c](http://greyhat.dk/toolbox/dns_amplification.c "Example of DNS amplification")
only demonstrates how its done and is not suitable for a realworld
effective DOS. Buffering request like "the low bit ion cannon" and using
several toplevel soa request (.com, .eu, .edu etc) and adding lots of
DNS servers would make it effective.

How to defend against this attack
=================================

Since this is a bandwidth attack its a matter of having enough bandwidth
and being able to reject it. It might sound easy but its quite common to
see attacks using more than 1Gbit/s and this is where your standard
firewall most likely is already flooded and can no longer process data.
This is where the ISP comes in and can help prevent the attack by
blocking the attack in the core network.

Now [openresolverproject.org](http://openresolverproject.org/ "Openresolver project")
uncovered a lot of open DNS resolvers (Roughly counted more than
20.000+) and if the attacker was using all these (And a botnet) and
assuming they all have a 1Gbit/s connection you could create a
19.5TBit/s attack!. We have already seen a 300Gbit/s attack on spamhaus
causing a major slowdown on the internet. But a 19.5TB attack would take
down large parts of the internet so of course no ISP can prevent this.

Why is this attack even possible
================================

Several parties besides the attacker come to mind here.

-  Software vendors for not making a better default configuration making
   it a open resolver per default
-  End users who install software not knowing how to prober configure
   the software
-  ISPs for not blocking spoofed traffic from their network (They should
   block outbound traffic that does not originate from the network)
-  ISPs for not telling the end user about this security issue and not
   acting on it (Blocking ports)
-  ISPs for not responding to abuse complaints

As it is now things will never get fixed. Spamhaus created a lookup
database for open dns resolvers (So ISP could block for these
misconfigred servers) but since the ISP properly would loose customers
due to blocking they will never use it (And they would have to use
excessive CPU on the border routers to handle it). And since there is no
law to actually get abuse complaints enforced the ISP will not take
responsibility. So it all comes down to money in the end.

The way I would like it to work is to simply

-  Create a abuse report to the ISP and CC ripe (or a taskforce for
   handling abuse world wide) for every abuse case
-  The task force should register the amount of abuse based on allocated
   subnet
-  Fail to handle abuse enough times and the task force should simply
   remove the subnet allocation removing the network from the ISP

This will make the ISP care about security since loosing IP's will force
their customers offline. And ISPs known to host spammers would simply be
shutdown by loosing all their IPs.

The last DNS amplification I handled I created a script for creating
abuse reports. Just to take the top 2 abuse accounts from the list of
open resolvers

```sh
        189 abuse@oneandone.net
       1503 abuse@ovh.net
```

So 1503 servers with open resolvers from one single ISP .. Created a
abuse report on this within 12 hours of the incident (More than 10 days
ago) and all of these servers are still online and I never heard a
single word (Weird enough this seems to be the standard not to reply).
