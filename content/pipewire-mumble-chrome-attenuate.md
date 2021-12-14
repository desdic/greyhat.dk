+++
title = "Attenuate in mumble using pipewire"
date = "2021-12-14T12:40:33-01:00"
publishdate = "2018-01-12"
categories =["pipewire"]
tags = ["Mumble", "Chrome", "Pipewire"]
slug = "pipewire-mumble-chrome-attenuate"
project_url = "https://greyhat.dk/pipewire-mumble-chrome-attenuate"
type = "post"
description = "Fixing attenuate in mumble using pipewire/chrome"
image = "pipewire.gif"
image_alt = "Pipewire logo"
+++

So if you like me is having problems with attenuate in Mumble that does not turn down the volumne from Chrome here is a little tip my co-worker found.

First test it by running

```sh
$ pw-loopback -m '[ FL FR ]' --capture-props='media.class=Audio/Sink node.name=my_sink' --playback-props='node.target="my-default-sink"'
```

and then change the sink of Chrome (I changed it using pavucontrol under Playback). 

If this worked here is how to make it permanent. Create a local configuration for pipewire

```sh
$ mkdir -p ~/.config/pipewire
$ cp /usr/share/pipewire/pipewire.conf ~/.config/pipewire/
```

Now edit the file and enable data-loop.library and add the config under context.modules like this


```
context.properties = {
...
     context.data-loop.library.name.system = support/libspa-support
}
...
context.modules = [
...
     {   name = libpipewire-module-loopback
         args = {
             node.name = "my_sink"
             audio.position = "FL,FR"
             capture.props = {
                 node.description = "my_sink"
                 media.class = "Audio/Sink"
             }
             playback.props = {
                 node.target = "my-default-sink"
             }
         }
     }
]
...
```

Then restart pipewire

```sh
$ systemctl --user restart pipewire.service
```
