+++
title = "Setting variables in a package on build time"
date = "2018-01-18T09:21:45-02:00"
publishdate = "2018-01-18"
categories =["go"]
tags = ["go", "ldflags"]
slug = "go-package-variables"
project_url = "https://greyhat.dk/go-package-variables"
type = "post"
description = "Setting variables at runtime for versions and other stuff"
image = "go.png"
image_alt = "Go's gopher"
+++

##  Setting variables in a package on build time

When building a go binary its possible to add ldflags in order to variables in build time (Like version numbers) and this is pretty well documented. But setting variables in internal/vendoring directories it not well documented.

This is how its done

```sh
test # tree
.
├── cmd
│   └── cli
│       └── main.go
├── internal
│   └── cmd
│       └── version.go
```

test/cmd/cli/main.go
```go
package main

import "fmt"
import "test/internal/cmd"

func main() {

    fmt.Printf("Version: %s\n", cmd.Getversion())
}
```

test/internal/cmd/version.go
```go
package cmd

var version = "Not set"

func Getversion() string {
    return version
}
```

This has to be done with full path like
```sh
# go build -ldflags "-X test/internal/cmd.version=1.0.0-0529a3e" -o test ./cmd/cli/*.go
# ./test
Version: 1.0.0-0529a3e
```

