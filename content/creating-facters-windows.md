+++
title = "Creating facters on Windows"
description = "Creating facters on Windows"
date ="2014-10-25"
publishdate ="2014-10-25"
categories = ["automation"]
tags = ["puppet", "windows"]
slug =  "creating-facters-windows"
project_url = "https://greyhat.dk/creating-facters-windows"
type = "post"
+++

I've done automation with puppet for nearly 3 years on Linux but
recently I have been tasked (work) with some automation on Windows. To
tell you the truth I'm not exactly a fan of windows and never will be
but I like a challenge.

But for this particular tasks I needed a list of logical drives and a
list of network adaptors and I couldn't find anyone who had already
created these facters.

[Puppetlabs](http://puppetlabs.com/ "Puppetlabs") contains a lot of resources when
it comes to Linux but almost none for Windows. It took me a while before
I finally found something I could use so I'd like to share what I found.

WMI (Windows Management Instrumentation) provides a interface to a lot
of resources on a host. Microsoft made their WMI classes public
available at their
site [Microsoft](http://msdn.microsoft.com/en-us/library/aa389273\(v=vs.85\).aspx "MSDN").

After finding the right WMI class a simple powershell script can test
the query before we put it in a facter.


```sh
    PS C:\Users\Administrator> $q = 'Win32_NetworkAdapter where AdapterType="Ethernet 802.3" and Speed > 100'
    PS C:\Users\Administrator> Get-WmiObject $q


    ServiceName      : vmxnet3ndis6
    MACAddress       : 00:50:xx:xx:xx:xx
    AdapterType      : Ethernet 802.3
    DeviceID         : 10
    Name             : vmxnet3 Ethernet Adapter
    NetworkAddresses :
    Speed            : 10000000000

    ServiceName      : vmxnet3ndis6
    MACAddress       : 00:50:xx:xx:xx:xx
    AdapterType      : Ethernet 802.3
    DeviceID         : 14
    Name             : vmxnet3 Ethernet Adapter #2
    NetworkAddresses :
    Speed            : 10000000000
```

The above gives a list of all ethernet adapters using
[802.3](http://en.wikipedia.org/wiki/IEEE_802.3 "IEEE 802.3 on wikipedia"). So next we can
transfer this to facters.

Get all 802.3 network adapters:

```ruby
    require 'facter/util/wmi'

    Facter.add(:networkadapters) do
         confine :kernel => %{windows}
         setcode do
            require 'facter/util/wmi'
            adapters = []

         Facter::Util::WMI.execquery("select * from Win32_NetworkAdapter where AdapterType='Ethernet 802.3' and Speed > 100").each do |ole|
                adapters.push("#{ole.Name}")
             end
            adapters.sort.join(',')
         end
    end
```

Get all logical (local) drives:

```ruby
    require 'facter/util/wmi'

    Facter.add(:logical_drives) do
         confine :kernel => %{windows}
         setcode do
            require 'facter/util/wmi'
            drives = []

         Facter::Util::WMI.execquery("select * from Win32_LogicalDisk where DriveType=3").each do |ole|
                drives.push("#{ole.DeviceID}")
             end
            drives.sort.join(',')
         end
    end
```

How and where facters are put on the Puppet Enterprise installation is
beyond the scope of this post and can easily be found at
[Puppetlabs](http://puppetlabs.com/ "Puppetlabs") website.

The above was tested on a Windows 2012 (64bit) using PE 3.3.x
