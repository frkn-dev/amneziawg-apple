package main

import (
	"fmt"
	"testing"

	"github.com/amnezia-vpn/amnezia-libxray/xray"
)

func TestPingH2(t *testing.T) {
	res := xray.Ping("", "/tmp/h2-probe.json", 8, "https://www.google.com/generate_204", "socks5://127.0.0.1:11081")
	fmt.Printf("H2 ping result: %q\n", res)
}
