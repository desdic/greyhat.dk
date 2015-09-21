+++
title ="Missing unread mail count in the dock on Mac OS X 10.9 (Mavericks)"
date = "2014-05-08"
publishdate = "2014-05-08"
categories = ["OS X"]
tags = ["Mac", "mail", "Mavericks", "OS X"]
slug = "missing-unread-mail-count-in-the-doc-on-mac-os-x-10-9-mavericks"
project_url = "https://greyhat.dk/missing-unread-mail-count-in-the-doc-on-mac-os-x-10-9-mavericks"
type = "post"
+++

I've had plenty of issues with mail in Mac OS X but most of them have
been related to the poor implementation of the integration with
Exchange. But I have finally found a solution for one specific problem.
That is the missing unread count in the dock.

This is how I fixed it. Quit mail entirely and run from a command prompt

```sh
    # mv ~/Library/Mail/V2/MailData/Envelope* ~/Desktop/
```

Not open mail once again and it will do a import of all mails (Took
about 2 hours on my machine but it depends on how many mails and mail
accounts you have).

Once verified that this works for you, you are safe to delete the
Evelope files placed on your desktop.

If this still does not work I'd bet you forgot to add mail to the
notification bar like this: Go to System Preferences > Notifications >
Mail, and make sure that the "Badge app icon" box is checked.
