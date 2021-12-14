+++
title = "USG Ubiquiti IPv6 via DHCP"
date = "2018-01-12T23:32:33-02:00"
publishdate = "2018-01-12"
categories =["Network"]
tags = ["IPv6", "Ubiquiti", "USG"]
slug = "usg-ubiquiti-ipv6"
project_url = "https://greyhat.dk/usg-ubiquiti-ipv6"
type = "post"
description = "Fixing issues with IPv6 not working on USG"
image = "ubiquti.png"
image_alt = "Unifi logo"
+++

I recently bought a Ubiquiti USG which was quite easy to setup. The only problem I had was that it didn't give out any IPv6 addresses to my clients (But router advertisement did work). My ISP gives a /48 as IPv6 delegated prefix but the USG wound't just use that and the GUI in version 5.6.29 does not support IPv6 yet. Several documents states that you just need to enable it by adding this config.gateway.json

```
{
        "firewall": {
                "ipv6-name": {
                        "wan_in-6": {
                                "default-action": "drop",
                                "description": "wan_in",
                                "enable-default-log": "''",
                                "rule": {
                                        "1": {
                                                "action": "accept",
                                                "description": "Allow Enabled/Related state",
                                                "state": {
                                                        "established": "enable",
                                                        "related": "enable"
                                                }
                                        },
                                        "2": {
                                                "action": "drop",
                                                "description": "Drop Invalid state",
                                                "log": "enable",
                                                "state": {
                                                        "invalid": "enable"
                                                }
                                        },
                                        "5": {
                                                "action": "accept",
                                                "description": "Allow ICMPv6",
                                                "log": "enable",
                                                "protocol": "icmpv6"
                                        }
                                }
                        },
                        "wan_local-6": {
                                "default-action": "drop",
                                "description": "wan_local",
                                "enable-default-log": "''",
                                "rule": {
                                        "1": {
                                                "action": "accept",
                                                "description": "Allow Enabled/Related state",
                                                "state": {
                                                        "established": "enable",
                                                        "related": "enable"
                                                }
                                        },
                                        "2": {
                                                "action": "drop",
                                                "description": "Drop Invalid state",
                                                "log": "enable",
                                                "state": {
                                                        "invalid": "enable"
                                                }
                                        },
                                        "5": {
                                                "action": "accept",
                                                "description": "Allow ICMPv6",
                                                "log": "enable",
                                                "protocol": "icmpv6"
                                        },
                                        "6": {
                                                "action": "accept",
                                                "description": "DHCPv6",
                                                "destination": {
                                                        "port": "546"
                                                },
                                                "protocol": "udp",
                                                "source": {
                                                        "port": "547"
                                                }
                                        }
                                }
                        }
                }
        },
        "interfaces": {
                "ethernet": {
                        "eth0": {
                                "dhcpv6-pd": {
                                        "pd": {
                                                "0": {
                                                        "interface": {
                                                                "eth1": "''"
                                                        },
                                                        "prefix-length": "64"
                                                }
                                        },
                                        "rapid-commit": "enable"
                                },
                                "firewall": {
                                        "in": {
                                                "ipv6-name": "wan_in-6"
                                        },
                                        "local": {
                                                "ipv6-name": "wan_local-6"
                                        }
                                }
                        },
                        "eth1": {
                                "ipv6": {
                                        "dup-addr-detect-transmits": "1",
                                        "router-advert": {
                                                "cur-hop-limit": "64",
                                                "link-mtu": "0",
                                                "managed-flag": "true",
                                                "max-interval": "600",
                                                "other-config-flag": "false",
                                                "prefix": {
                                                        "::/64": {
                                                                "autonomous-flag": "true",
                                                                "on-link-flag": "true",
                                                                "valid-lifetime": "2592000"
                                                        }
                                                },
                                                "reachable-time": "0",
                                                "retrans-timer": "0",
                                                "send-advert": "true"
                                        }
                                }
                        }
                }
        }
}

```

to the controllers path /var/lib/unifi/sites/default/ and force a provisioning but that didn't work for me. My router got the IPv6 from the ISP and then eth1 got the prefix but no clients got any addresses.

```
ubnt@USG:~$ show version
Version:      v4.4.12
Build ID:     5032482
Build on:     11/03/17 15:38
Copyright:    2012-2017 Ubiquiti Networks, Inc.
HW model:     UniFi-Gateway-3
HW S/N:       xxxxxxxxxxxx
Uptime:       23:23:03 up 1 day,  2:11,  1 user,  load average: 0.06, 0.09, 0.10
ubnt@USG:~$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN 
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN 
    link/ether 78:xx:xx:xx:xx:xx brd ff:ff:ff:ff:ff:ff
    inet 212.xxx.xxx.xxx/26 brd 212.xxx.xxx.xxx scope global eth0
       valid_lft forever preferred_lft forever
    inet6 2a00:xxxx:xxxx:xxxx:xxxx:xxxx/128 scope global 
       valid_lft forever preferred_lft forever
    inet6 fe80::xxxx:xxxx:xxxx:xxxx/64 scope link 
       valid_lft forever preferred_lft forever
3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN 
    link/ether 78:xx:xx:xx:xx:xx brd ff:ff:ff:ff:ff:ff
    inet 192.168.1.1/24 brd 192.168.1.255 scope global eth1
       valid_lft forever preferred_lft forever
    inet6 2a00:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx/48 scope global 
       valid_lft forever preferred_lft forever
    inet6 fe80::xxxx:xxxx:xxxx:xxxx/64 scope link 
       valid_lft forever preferred_lft forever
4: eth2: <BROADCAST,MULTICAST> mtu 1500 qdisc noqueue state DOWN 
    link/ether 78:xx:xx:xx:xx:xx brd ff:ff:ff:ff:ff:ff
5: imq0: <NOARP,UP,LOWER_UP> mtu 16000 qdisc pfifo_fast state UNKNOWN qlen 11000
    link/void
```

for some reason it seems that the USG cannot carve a /64 from the /48 so when I replaced the ::/64 with

```
...
                        "eth1": {
                                "ipv6": {
                                        "dup-addr-detect-transmits": "1",
                                        "router-advert": {
                                                "cur-hop-limit": "64",
                                                "link-mtu": "0",
                                                "managed-flag": "true",
                                                "max-interval": "600",
                                                "other-config-flag": "false",
                                                "prefix": {
                                                        "2a00:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx/64": {
                                                                "autonomous-flag": "true",
                                                                "on-link-flag": "true",
                                                                "valid-lifetime": "2592000"
                                                        }
                                                },
                                                "reachable-time": "0",
                                                "retrans-timer": "0",
                                                "send-advert": "true"
                                        }
                                }
                        }
...
```

and did a provisioning all clients got an IPv6. You can also test it by ssh'ing to the USG and

```sh
$ configure
$ set interfaces ethernet eth1 ipv6 router-advert prefix 2a00:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx/64
$ commit
```
