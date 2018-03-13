+++
title = "USG Ubiquiti VPN using Strongswan"
date = "2018-03-13T17:36:33-02:00"
publishdate = "2018-03-13"
categories =["Network"]
tags = ["IPsec", "Ubiquiti", "USG", "VPN", "L2TP"]
slug = "usg-ubiquiti-strongswan"
project_url = "https://greyhat.dk/usg-ubiquiti-strongswan"
type = "post"
+++

##  USG VPN using Strongswan

Been trying to find a guide on how to setup IPsec/L2TP between USG and Linux but haven't really found one that worked for me so this is how I have made it work.

### The USG

There are tons of guides and videos on how to set it up on the USG so I'll just provide a few notes on that.

Created a network
![VPN network](/ubiquti-vpn-network.png)

Turned on the server and added a preshared key
![Radius server](/ubiquty-vpn-radius-server.png)

Added a user
![Radius user](/ubiquti-vpn-radius-user.png)

### Linux

On my laptop running Linux (Arch) I installed strongswan and xl2tpd) (currently strongswan version 5.6.2-1 and xl2tpd version 1.3.10-1)

```sh
# pacaur -S strongswan xl2tpd
```

Configured ipsec.conf as a road-warrior setup

/etc/ipsec.conf
```
# ipsec.conf - strongSwan IPsec configuration file

# basic configuration

config setup
  # strictcrlpolicy=yes
  # uniqueids = no

conn %default
  ikelifetime=60m
  keylife=20m
  rekeymargin=3m
  keyingtries=1
  keyexchange=ikev1
  authby=secret
  ike=aes128-sha1-modp1024,3des-sha1-modp1024!
  esp=aes128-sha1-modp1024,3des-sha1-modp1024!

conn myvpn
  keyexchange=ikev1
  left=%defaultroute
  auto=add
  authby=secret
  type=transport
  leftprotoport=17/1701
  rightprotoport=17/1701
  right=<public USG address here>
```

/etc/ipsec.secrets
```
: PSK "<insert pre-shared key here>"
```

```sh
# chmod 600 /etc/ipsec.secrets
```


/etc/xl2tpd/xl2tpd.conf
```
[lac myvpn]
lns = <public USG address here>
ppp debug = yes
pppoptfile = /etc/ppp/options.l2tpd.client
length bit = yes
```

/etc/ppp/options.l2tpd.client
```
ipcp-accept-local
ipcp-accept-remote
refuse-eap
require-chap
noccp
noauth
mtu 1280
mru 1280
noipdefault
defaultroute
usepeerdns
connect-delay 5000
name <insert username here>
password <insert password here>
```

```sh
# chmod 600 /etc/ppp/options.l2tpd.client
```

Started the tunnel and asked for an IP

```sh
# mkdir -p /var/run/xl2tpd
# touch /var/run/xl2tpd/l2tp-control
# systemctl start strongswan.service
# systemctl start xl2tpd.service
# ipsec up myvpn
initiating Main Mode IKE_SA myvpn[1] to xxx.xxx.xxx.xxx
generating ID_PROT request 0 [ SA V V V V V ]
sending packet: from 10.78.16.144[500] to xxx.xxx.xxx.xxx[500] (212 bytes)
received packet: from xxx.xxx.xxx.xxx[500] to 10.78.16.144[500] (136 bytes)
parsed ID_PROT response 0 [ SA V V V ]
received XAuth vendor ID
received DPD vendor ID
received NAT-T (RFC 3947) vendor ID
generating ID_PROT request 0 [ KE No NAT-D NAT-D ]
sending packet: from 10.78.16.144[500] to xxx.xxx.xxx.xxx[500] (244 bytes)
received packet: from xxx.xxx.xxx.xxx[500] to 10.78.16.144[500] (244 bytes)
parsed ID_PROT response 0 [ KE No NAT-D NAT-D ]
local host is behind NAT, sending keep alives
generating ID_PROT request 0 [ ID HASH N(INITIAL_CONTACT) ]
sending packet: from 10.78.16.144[4500] to xxx.xxx.xxx.xxx[4500] (108 bytes)
received packet: from xxx.xxx.xxx.xxx[4500] to 10.78.16.144[4500] (76 bytes)
parsed ID_PROT response 0 [ ID HASH ]
IKE_SA myvpn[1] established between 10.78.16.144[10.78.16.144]...xxx.xxx.xxx.xxx[xxx.xxx.xxx.xxx]
scheduling reauthentication in 3275s
maximum IKE_SA lifetime 3455s
generating QUICK_MODE request 521266606 [ HASH SA No KE ID ID NAT-OA NAT-OA ]
sending packet: from 10.78.16.144[4500] to xxx.xxx.xxx.xxx[4500] (364 bytes)
received packet: from xxx.xxx.xxx.xxx[4500] to 10.78.16.144[4500] (332 bytes)
parsed QUICK_MODE response 521266606 [ HASH SA No KE ID ID NAT-OA NAT-OA ]
CHILD_SA myvpn{1} established with SPIs cfbb01aa_i c9318f91_o and TS 10.78.16.144/32[udp/l2f] === xxx.xxx.xxx.xxx/32[udp/l2f]
connection 'myvpn' established successfully
# echo "c myvpn" > /var/run/xl2tpd/l2tp-control
```

```sh
# ip r
default via 192.168.43.1 dev wlp4s0 proto dhcp src 192.168.43.153 metric 20
10.255.255.0 dev ppp0 proto kernel scope link src 172.18.100.1
192.168.43.0/24 dev wlp4s0 proto kernel scope link src 192.168.43.153
192.168.43.1 dev wlp4s0 proto dhcp scope link src 192.168.43.153 metric 20
```

Now you can add routes that you want to go to via VPN.
