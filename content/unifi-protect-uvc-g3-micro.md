+++
title = "UVC G3 Micro wifi issues"
date = "2020-06-26T08:28:31-02:00"
publishdate = "2020-06-26"
categories =["Network"]
tags = ["unifiprotect", "uvc", "g3", "micro", "camera", "wifi", "Ubiquiti"]
slug = "uvc-g3-micro-wifi"
project_url = "https://greyhat.dk/uvc-g3-micro-wifi"
type = "post"
+++

## UVC G3 Micro wifi issues

Oki so lately I bought a UVC-G3 Micro to play with and once connected to Unifi
Protect it kept getting disconnected/re-connecting and it would only connect using 2.4Ghz.
After searching about this problem I found several others having the same
problem. It turns out that the camera does not support the wifi channels here
in europe per default and the interface (In both Unifi Protect and on the cam
has no options for it). This is how I fixed my setup using

| Type | Version |
| :--- | :--- |
| Controller  | 1.13.3 |
| Web UI  | 1.20.0 |
| UVC  | v4.23.7.67 |


## Allow ssh into the camera on the cloud key

Using the same credentials as loggin into the cloud key webinterface and edit /usr/etc/unifi-protect/config.json to add the enableSsh option. Then restart the controller

```sh
# ssh 192.168.1.146 -l me@example.com
Linux Example 3.18.44-ubnt-qcom #1 SMP Thu Apr 30 09:50:05 UTC 2020 aarch64

Firmware version: v1.1.13
                .--.__
  ______ __ .--(    ) )-.   __ __                    __
 |      |  (._____.__.___)_|  |  |__ _____ __ __   _|  |_
 |   ---|  ||  _  |  |  |  _  |    <|  -__|  |  | |_    _|
 |______|__||_____|_____|_____|__|__|_____|___  |   |__|
        (c) 2019 Ubiquiti Networks, Inc.  |_____|

      Welcome to the CloudKey Plus!
Last login: Thu Jun 25 18:00:39 2020 from 192.168.1.145
root@Example:~#
```

Edit /usr/etc/unifi-protect/config.json so it has the enableSsh options
```json
{
  "ssl": {
    "crt": "/etc/ssl/private/cloudkey.crt",
    "key": "/etc/ssl/private/cloudkey.key"
  },
  "backupPaths": [ "/etc/unifi-protect/backups", "/data/unifi-protect/backups" ],
  "mbToKeepFree": 32768,
  "enableSsh": true
}
```

Then restart Unifi Protect

```sh
root@Example:~# systemctl restart unifi-protect
```

Give a few seconds before the information is sent to the camera.

## Change region on the UVC G3 Micro

Now that ssh is enabled login to the camera using ssh (default is ubnt/ubnt otherwise the device password is in the Unifi Protects interface in Settings->Advanced->Device password)

```sh
# ssh 192.168.1.147 -l ubnt
ubnt@192.168.1.147's password:

BusyBox v1.29.2 () built-in shell (ash)

UVC.v4.23.7.67# ubnt_system_cfg write custom.region 0x80d0 && cfgmtd -w -p /etc && reboot
```

Now my camera connects to 5Ghz and works really well.

## Regions

The region I use is for Denmark but you can find the one you need using the ar6002 firmware country codes list. A few of them are here

| Regions | ID |
| :---- | :--- |
| DK | 0x80d0 |
| UK | 0x833a |
| CZ | 0x80cb | 
