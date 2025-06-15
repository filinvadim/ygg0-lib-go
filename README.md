# ygg0-lib-go
Embedded Yggdrasil networking for Go applications. No TUN required. No external daemon. Direct mesh routing.

## Overview

`ygg0_lib_go` is a Go library that embeds the [Yggdrasil Network](https://yggdrasil-network.github.io/) core directly into your 
application. It provides an easy-to-use wrapper to bootstrap a mesh node, manage peers, and enable 
secure IPv6 overlay networking, with optional support for multicast discovery and TUN interfaces.

---

## Installation

```bash
go get github.com/filinvadim/ygg0-lib-go
````

---

## Example

```go
package main

import (
	"context"
	"log"
	"net"
	"os"

	ygg "github.com/filinvadim/ygg0_lib_go"
)

func main() {
	ctx := context.Background()

	router, err := ygg.NewMeshRouter(ctx, ygg.Config{
		Logger:         log.New(os.Stdout, "[mesh] ", log.LstdFlags),
		PrivateKey:     [32]byte{}, // Optional: load your own key
		PublicNodes:    []string{"tls://203.0.113.1:443"},
		ListenAddrs:    []string{"tls://0.0.0.0:0"},
		TunEnabled:     false,
		MulticastEnabled: false,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer router.Stop()

	log.Println("Mesh Node ID:", router.HumanReadableID())
	log.Println("Listening at:", router.LocalAddress())
}
```

---

## License

LGPL License. See [LICENSE](./LICENSE) for details.

---

## Disclaimer

This project is not officially affiliated with the Yggdrasil Network team, 
but reuses code from the [official Yggdrasil Go implementation](https://github.com/yggdrasil-network/yggdrasil-go).


