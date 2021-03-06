+++
title ="The lost art of debugging for admins #part 2 – Basic knowledge of protocols"
date ="2014-01-03"
publishdate ="2014-01-03"
categories =["Debugging"]
slug = "the-lost-art-of-debugging-for-admins-part-2-basic-knowledge-of-protocols"
project_url = "https://greyhat.dk/the-lost-art-of-debugging-for-admins-part-2-basic-knowledge-of-protocols"
type = "post"
+++

Protocols
=========

Just a little knowledge about a few protocols can get you a long way
when debugging. Often, clients does not give the full feedback from the
server or tries to give a user-friendly error message which just makes
it worse. Here is how just a handfuld of protocols can be used using
telnet/openssl

HTTP/HTTPS
==========

```sh
    $ telnet www.example.com 80
    Connected to www.example.com.
    Escape character is '^]'.
    GET / HTTP/1.1
    HOST: www.example.com
    User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.4) Gecko/20070515 Firefox/2.0.0.4

    HTTP/1.1 302 Found
    Date: Mon, 18 Nov 2013 19:32:49 GMT
    Server: Apache
    Location: https://www.example.com/
    Content-Length: 206
    Connection: close
    Content-Type: text/html; charset=iso-8859-1302 Found

    <!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
    <html><head>
    <title>302 Found</title>
    </head><body>
    <h1>Found</h1>
    <p>The document has moved <a href="https://www.example.com/index.htm">here</a>.</p>
    </body></html>
    Connection closed by foreign host.
```

```sh
    $ openssl s_client -connect www.example.com:443
    CONNECTED(00000003)
    ---
    Lots of SSL certificate stuff removed
    ---

    GET / HTTP/1.1
    HOST: www.example.com

    HTTP/1.1 200 OK
    Date: Mon, 18 Nov 2013 19:37:18 GMT
    Server: Apache
    Last-Modified: Tue, 29 Jan 2013 07:51:17 GMT
    ETag: "e83f7c0-1e8-4d468a89c0237"
    Accept-Ranges: bytes
    Content-Length: 488
    Connection: close
    Content-Type: text/html<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" /><meta name="Description" content="www.example.com: My private homepage" />Example.com
    <link href="/styles-site.css" rel="stylesheet" type="text/css" /></code></pre>
    <div>

    Example.com test site

    </div>
```

POP3/POP3S
==========

```sh
    $ telnet example.com 110
    Connected to example.com.
    Escape character is '^]'.
    +OK Yes master.
    user user@example.com
    +OK
    pass secret
    +OK Logged in.
    list
    +OK 2 messages:
    1 2001
    2 1863
    stat
    +OK 2 14989176
    retr 2
    +OK 12138 octets
```

Just like the example with https the openssl client works for POP3

IMAP/IMAPS
==========

```sh
    $ telnet example.com 143
    Connected to example.com.
    Escape character is '^]'.
    * OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE STARTTLS AUTH=PLAIN] Yes master.
    A001 LOGIN user@example.com secret
    A001 OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE SORT SORT=DISPLAY THREAD=REFERENCES THREAD=REFS MULTIAPPEND UNSELECT IDLE CHILDREN NAMESPACE UIDPLUS LIST-EXTENDED I18NLEVEL=1 CONDSTORE QRESYNC ESEARCH ESORT SEARCHRES WITHIN CONTEXT=SEARCH LIST-STATUS] Logged in
    A002 LIST "" "*"
    * LIST (\HasChildren) "." "INBOX"
    * LIST (\HasNoChildren) "." "INBOX.Drafts"
    * LIST (\HasNoChildren) "." "INBOX.Junk"
    * LIST (\HasNoChildren) "." "INBOX.Sent"
    * LIST (\HasNoChildren) "." "INBOX.Trash"
    A002 OK List completed.
    A003 EXAMINE INBOX
    * FLAGS (\Answered \Flagged \Deleted \Seen \Draft Junk NonJunk $label1 $label4 $label2 $label3 $label5 $MDNSent $Forwarded $NotJunk $Junk JunkRecorded receipt-handled $MailFlagBit0 $MailFlagBit1)
    * OK [PERMANENTFLAGS ()] Read-only mailbox.
    * 2 EXISTS
    * 0 RECENT
    * OK [UNSEEN 1] First unseen.
    * OK [UIDVALIDITY 1214564994] UIDs valid
    * OK [UIDNEXT 39761] Predicted next UID
    * OK [HIGHESTMODSEQ 35521] Highest
    A003 OK [READ-ONLY] Select completed.
    A004 FETCH 1 BODY[]
    * 1 FETCH (BODY[] {2001}
    ..
```

SMTP/SMTPS
==========

```sh
    $ telnet example.com 25
    Trying 192.168.1.1...
    Connected to example.com.
    Escape character is '^]'.
    220 example.com ESMTP
    ehlo example.com
    250-example.com
    250-PIPELINING
    250-SIZE
    250-ETRN
    250-STARTTLS
    250-AUTH PLAIN LOGIN
    250-AUTH=PLAIN LOGIN
    250-ENHANCEDSTATUSCODES
    250-8BITMIME
    250 DSN
    mail from:<whomever@example.com>
    250 2.1.0 Ok
    rcpt to:<user@example.com>
    250 2.1.5 Ok
    data
    354 End data with <CR><LF>.<CR><LF>
    Subject: Testing
    Test test
    .
    250 2.0.0 Ok: queued as 2DAB5C13D8A
    quit
    221 2.0.0 Bye
    Connection closed by foreign host.
```

Tips on reading/creating emails
===============================

Attached files are added as mime-encoded base64 blocks like so

```
    Return-Path: <user@example.com>
    X-Original-To: user@example.com
    Delivered-To: user@example.com
    Received: from [192.168.1.1] (example.com [192.168.1.1])
        (using TLSv1 with cipher AES128-SHA (128/128 bits))
        (No client certificate requested)
        (Authenticated sender: user@example.com)
        by example.com (Postfix) with ESMTPSA id 13398C13CE4
        for <user@example.com> Fri,  3 Jan 2014 13:01:22 +0100 (CET)
    From: Example User <user@example.com>
    Content-Type: image/png; x-mac-hide-extension=yes; x-unix-mode=0644; name="dot.png"
    Content-Transfer-Encoding: base64
    Subject: img
    Message-Id: <470CCFDB-8106-4F2A-8BB3-ED4765D45551@example.com>
    Date: Fri, 3 Jan 2014 13:01:25 +0100
    To: Example User <user@example.com>
    Mime-Version: 1.0 (Mac OS X Mail 7.1 \(1827\))
    Content-Disposition: inline; filename=dot.png
    X-Mailer: Apple Mail (2.1827)

    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
    1Y/YjpwY9R29/nzB8+EX4hcTLwv+Uvyr6pXxq+N/M//uGYsdG34teT35pvit2tu6d/bvusbDxh+/
    z3g/8aHwo9rHA58Yn7o/x3x+NrHsC+5L+VeTrx3fAr89nMyYnBRzJJzpXACFtHByMgBv6gCgxAFA
    vY7kC3IzefG0BTSTyyMMfa9T8n/xTO48NYDkEKCOCUA0goF5AOzrBMAA6YlIH8YEIJIJYDs7WQUz
    JTPZznaaIFIrkpqUTU6+RfJBnAkAX/snJydaJye/1iL5+30AOt/P5ONT1gqHAGDmsXxDgq4qKs04
    +kf7H19W/ovOQJzqAAABm2lUWHRYTUw6Y29tLmFkb2JlLnhtcAAAAAAAPHg6eG1wbWV0YSB4bWxu
    czp4PSJhZG9iZTpuczptZXRhLyIgeDp4bXB0az0iWE1QIENvcmUgNS40LjAiPgogICA8cmRmOlJE
    RiB4bWxuczpyZGY9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkvMDIvMjItcmRmLXN5bnRheC1ucyMi
    PgogICAgICA8cmRmOkRlc2NyaXB0aW9uIHJkZjphYm91dD0iIgogICAgICAgICAgICB4bWxuczpl
    eGlmPSJodHRwOi8vbnMuYWRvYmUuY29tL2V4aWYvMS4wLyI+CiAgICAgICAgIDxleGlmOlBpeGVs
    WERpbWVuc2lvbj4yMTwvZXhpZjpQaXhlbFhEaW1lbnNpb24+CiAgICAgICAgIDxleGlmOlBpeGVs
    WURpbWVuc2lvbj4yMjwvZXhpZjpQaXhlbFlEaW1lbnNpb24+CiAgICAgIDwvcmRmOkRlc2NyaXB0
    aW9uPgogICA8L3JkZjpSREY+CjwveDp4bXBtZXRhPgrUWcUnAAAB5ElEQVQ4EWNgGAUDGQKMRFiu
    El8ewfNw+9QVZyGKVdxT0wLNxTgY3j88z0KEfinXAG/lhwwQ/SoBjTPL3bgYfr5/z6CuwEKM/q8/
    fjL8/PMbYpNviD3Xz7sNDjE7wXwW49T+rgjJXSuumER4yHAxf354uCWi7BBIzq5xTq69hgzQBmZm
    hm8gEeOACB05bpa/758JBkSk8rPfPLqQWdU+0stAWcNQjfHZuVNPmVRVtQ3V/yzf/bVt9WQXFYGn
    53btPvNMXEOe4/2NBW+UZtTEKPAwMfHIW9hYGJqYyP25DXX/+6sbvFI6gTYsODBFRU5WJT7fUYb5
    4a7OiPoNQEFtT1tBoPWHOh0sO8uXHPBl2W4TAVQMAkxg8ufB6RA+9x8g/89vKSGg+r9X9gI1QwFI
    HBuA6IfJGBvLsTN8ev8OaAZI6CuIUIkPV2Fn+AtiYgEQ97NIWAS4qyompobxMrxfsmD2VwtzYKjp
    J5TH20nEhVmwMzB8w+EAiH5mi5hyC6DpP9/smtEwFZhMzk4/7NBraxKQYcLw5Mzh51q2kgy/ILZD
    KbhT7AoXHD9+oDHAWMVYBS4IYdi5B9gZo4mhc1kY2IBOYPn97uwdaOpEqDi0ExF+CFFUFsuzm2cv
    Xn125Rmq8IjhAQApUJ8sKnhyuAAAAABJRU5ErkJggg==
```

Paste the base64 encoded block to a file and decode it

```sh
    openssl base64 -d < dot_png.base64 > dot.png
```

Or manually encode a file/text

```sh
    openssl base64 -e > dot.png < dot_png.base64
```

All of the above is also used for penetration testing since you can test
for open relays, test for users, brute force attacks or looking for
version numbers (Just automate it with expect or netcat).
