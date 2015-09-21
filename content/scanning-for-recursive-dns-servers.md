+++
title ="Scanning for recursive DNS servers"
date ="2013-04-11"
publishdate ="2013-04-11"
categories = ["Security"]
tags = ["DNS Scanning"]
slug ="scanning-for-recursive-dns-servers"
project_url = "https://greyhat.dk/scanning-for-recursive-dns-servers"
type = "post"
+++

When working for an ISP it becomes pretty clear that you don't want your
customers or your network to participate in any attack. I wrote a small
perl script to find DNS servers open for recursive requests

[scandns.pl](http://greyhat.dk/toolbox/scandns.pl "Perl script for scanning for vulnerable DNS servers")

I found 19 misconfigured DNS servers. Now the real work starts by
contacting the owners.
