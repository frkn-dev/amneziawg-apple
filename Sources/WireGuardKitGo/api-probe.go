/* SPDX-License-Identifier: MIT
 *
 * WireGuard/AmneziaWG handshake probe: measures per-server availability
 * and RTT by running a real handshake against the endpoint and timing
 * the initiation -> response round trip.
 */

package main

// #include <stdlib.h>
import "C"

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/amnezia-vpn/amneziawg-go/tun/tuntest"
)

// probeBind wraps a conn.Bind and records the time the handshake initiation
// is sent (junk packets and the initiation travel in a single Send batch, so
// the last Send before a reply is the initiation) and the time the first
// packet (the handshake response) is received.
type probeBind struct {
	conn.Bind

	mu     sync.Mutex
	sentAt time.Time

	done     chan time.Duration
	doneOnce sync.Once
}

func (b *probeBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	b.mu.Lock()
	b.sentAt = time.Now()
	b.mu.Unlock()
	return b.Bind.Send(bufs, ep)
}

func (b *probeBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actualPort, err := b.Bind.Open(port)
	if err != nil {
		return nil, 0, err
	}
	wrapped := make([]conn.ReceiveFunc, len(fns))
	for i, fn := range fns {
		fn := fn
		wrapped[i] = func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
			n, err := fn(packets, sizes, eps)
			if n > 0 && err == nil {
				b.mu.Lock()
				sentAt := b.sentAt
				b.mu.Unlock()
				if !sentAt.IsZero() {
					rtt := time.Since(sentAt)
					b.doneOnce.Do(func() { b.done <- rtt })
				}
			}
			return n, err
		}
	}
	return wrapped, actualPort, nil
}

func probeKeyToHex(keyB64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(keyB64))
	if err != nil {
		return "", err
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("key must decode to 32 bytes, got %d", len(raw))
	}
	return hex.EncodeToString(raw), nil
}

// probeJunkLines converts the AWG junk params JSON ({"Jc": "3", ..., "H4": "...",
// values are strings) into uapi device config lines. Empty/zero values are skipped.
func probeJunkLines(junkParamsJSON string) ([]string, error) {
	junkParamsJSON = strings.TrimSpace(junkParamsJSON)
	if junkParamsJSON == "" || junkParamsJSON == "{}" {
		return nil, nil
	}
	var params map[string]string
	if err := json.Unmarshal([]byte(junkParamsJSON), &params); err != nil {
		return nil, err
	}
	keys := []string{"Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4"}
	var lines []string
	for _, key := range keys {
		value := strings.TrimSpace(params[key])
		if value == "" || value == "0" {
			continue
		}
		lines = append(lines, strings.ToLower(key)+"="+value)
	}
	return lines, nil
}

func probeRTT(host string, port int, clientPrivKeyB64, serverPubKeyB64, pskB64, junkParamsJSON string, timeout time.Duration) (time.Duration, error) {
	privHex, err := probeKeyToHex(clientPrivKeyB64)
	if err != nil {
		return 0, fmt.Errorf("client private key: %w", err)
	}
	pubHex, err := probeKeyToHex(serverPubKeyB64)
	if err != nil {
		return 0, fmt.Errorf("server public key: %w", err)
	}
	pskHex := strings.Repeat("0", 64)
	if strings.TrimSpace(pskB64) != "" {
		pskHex, err = probeKeyToHex(pskB64)
		if err != nil {
			return 0, fmt.Errorf("preshared key: %w", err)
		}
	}
	junkLines, err := probeJunkLines(junkParamsJSON)
	if err != nil {
		return 0, fmt.Errorf("junk params: %w", err)
	}

	logger := &device.Logger{
		Verbosef: func(string, ...interface{}) {},
		Errorf:   func(string, ...interface{}) {},
	}
	bind := &probeBind{Bind: conn.NewStdNetBind(), done: make(chan time.Duration, 1)}
	ctun := tuntest.NewChannelTUN()
	dev := device.NewDevice(ctun.TUN(), bind, logger)
	defer dev.Close()

	settings := []string{
		"private_key=" + privHex,
		"listen_port=0",
	}
	settings = append(settings, junkLines...)
	settings = append(settings,
		"public_key="+pubHex,
		"preshared_key="+pskHex,
		fmt.Sprintf("endpoint=%s:%d", host, port),
		"replace_allowed_ips=true",
		"allowed_ip=0.0.0.0/0",
		"allowed_ip=::/0",
	)
	if err := dev.IpcSet(strings.Join(settings, "\n")); err != nil {
		return 0, fmt.Errorf("ipc set: %w", err)
	}
	if err := dev.Up(); err != nil {
		return 0, fmt.Errorf("device up: %w", err)
	}

	// stage a packet to trigger the handshake initiation
	ping := tuntest.Ping(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"))
	select {
	case ctun.Outbound <- ping:
	case <-time.After(time.Second):
		return 0, fmt.Errorf("failed to stage trigger packet")
	}

	select {
	case rtt := <-bind.done:
		return rtt, nil
	case <-time.After(timeout):
		return 0, fmt.Errorf("timeout")
	}
}

//export WgProbeRTT
func WgProbeRTT(host *C.char, port C.int, clientPrivKeyB64 *C.char, serverPubKeyB64 *C.char, pskB64 *C.char, junkParamsJSON *C.char, timeoutMs C.int) C.int {
	timeout := time.Duration(timeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	rtt, err := probeRTT(C.GoString(host), int(port), C.GoString(clientPrivKeyB64), C.GoString(serverPubKeyB64), C.GoString(pskB64), C.GoString(junkParamsJSON), timeout)
	if err != nil {
		// stderr lands in the Xcode console / NE log capture
		fmt.Fprintf(os.Stderr, "[WGPROBE] %s:%d error: %v\n", C.GoString(host), int(port), err)
		return -1
	}
	return C.int(rtt.Milliseconds())
}
