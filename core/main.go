// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	boxservice "github.com/sagernet/sing-box/adapter/service"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/dns/transport/hosts"
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/http"
	"github.com/sagernet/sing-box/protocol/hysteria2"
	"github.com/sagernet/sing-box/protocol/mixed"
	"github.com/sagernet/sing-box/protocol/shadowsocks"
	"github.com/sagernet/sing-box/protocol/socks"
	"github.com/sagernet/sing-box/protocol/trojan"
	"github.com/sagernet/sing-box/protocol/vless"
	"github.com/sagernet/sing-box/protocol/vmess"
	"github.com/sagernet/sing-box/protocol/wireguard"
	"github.com/sagernet/sing/common/json"
)

const defaultConfigPath = "/data/ps5-local-proxy/config.json"
const maxConfigSize = 1024 * 1024
const proxyPort = 17890

func boxContext(ctx context.Context) context.Context {
	in := inbound.NewRegistry()
	mixed.RegisterInbound(in)

	out := outbound.NewRegistry()
	direct.RegisterOutbound(out)
	http.RegisterOutbound(out)
	hysteria2.RegisterOutbound(out)
	socks.RegisterOutbound(out)
	shadowsocks.RegisterOutbound(out)
	trojan.RegisterOutbound(out)
	vless.RegisterOutbound(out)
	vmess.RegisterOutbound(out)
	registerNaiveH2(out)

	endpoints := endpoint.NewRegistry()
	wireguard.RegisterEndpoint(endpoints)

	dnsTransports := dns.NewTransportRegistry()
	local.RegisterTransport(dnsTransports)
	hosts.RegisterTransport(dnsTransports)
	transport.RegisterUDP(dnsTransports)
	transport.RegisterTCP(dnsTransports)
	transport.RegisterTLS(dnsTransports)
	transport.RegisterHTTPS(dnsTransports)

	return box.Context(ctx, in, out, endpoints, dnsTransports,
		boxservice.NewRegistry(), certificate.NewRegistry())
}

func startProxy(ctx context.Context, config []byte) (*box.Box, netip.AddrPort, error) {
	ctx = boxContext(ctx)
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, config)
	if err != nil {
		return nil, netip.AddrPort{}, fmt.Errorf("decode config: %w", err)
	}
	if len(options.Inbounds) != 1 || options.Inbounds[0].Type != C.TypeMixed {
		return nil, netip.AddrPort{}, errors.New("configure one mixed inbound")
	}
	listener, ok := options.Inbounds[0].Options.(*option.HTTPMixedInboundOptions)
	loopback := netip.AddrFrom4([4]byte{127, 0, 0, 1})
	if !ok || listener.Listen.Build(netip.Addr{}) != loopback ||
		listener.ListenPort != proxyPort || listener.SetSystemProxy ||
		len(listener.Users) != 0 || (listener.TLS != nil && listener.TLS.Enabled) {
		return nil, netip.AddrPort{}, fmt.Errorf("the mixed inbound must use 127.0.0.1:%d without users, TLS or set_system_proxy", proxyPort)
	}
	listener.ReuseAddr = false
	for _, endpoint := range options.Endpoints {
		if wireGuard, ok := endpoint.Options.(*option.WireGuardEndpointOptions); ok {
			if wireGuard.System {
				return nil, netip.AddrPort{}, fmt.Errorf("endpoint %q: WireGuard requires system=false on PS5", endpoint.Tag)
			}
			if !validWireGuardKey(wireGuard.PrivateKey) {
				return nil, netip.AddrPort{}, fmt.Errorf("endpoint %q: private_key must be a 32-byte base64 key", endpoint.Tag)
			}
			for i, peer := range wireGuard.Peers {
				if !validWireGuardKey(peer.PublicKey) {
					return nil, netip.AddrPort{}, fmt.Errorf("endpoint %q peer %d: public_key must be a 32-byte base64 key", endpoint.Tag, i+1)
				}
				if peer.PreSharedKey != "" && !validWireGuardKey(peer.PreSharedKey) {
					return nil, netip.AddrPort{}, fmt.Errorf("endpoint %q peer %d: pre_shared_key must be a 32-byte base64 key", endpoint.Tag, i+1)
				}
			}
			if wireGuard.Workers == 0 {
				wireGuard.Workers = 2
			}
		}
	}
	if options.Log == nil {
		options.Log = &option.LogOptions{Level: "info"}
	}
	options.Log.DisableColor = true
	options.Log.Output = ""

	proxy, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		return nil, netip.AddrPort{}, fmt.Errorf("initialize core: %w", err)
	}
	if err := proxy.Start(); err != nil {
		return nil, netip.AddrPort{}, fmt.Errorf("start core: %w", err)
	}
	return proxy, netip.AddrPortFrom(loopback, listener.ListenPort), nil
}

func validWireGuardKey(key string) bool {
	var decoded [33]byte
	if len(key) != base64.StdEncoding.EncodedLen(32) {
		return false
	}
	n, err := base64.StdEncoding.Decode(decoded[:], []byte(key))
	return n == 32 && err == nil
}

func readConfig(path string) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("the config must be a regular file")
	}
	config, err := io.ReadAll(io.LimitReader(file, maxConfigSize+1))
	if err != nil {
		return nil, err
	}
	if len(config) > maxConfigSize {
		return nil, errors.New("the config exceeds 1 MiB")
	}
	fmt.Fprintln(os.Stderr, "Loaded profile from", path)
	return config, nil
}

func managedProxy(ctx context.Context, control io.Writer, commands <-chan byte) error {
	config, err := readConfig(defaultConfigPath)
	if err != nil {
		return err
	}
	proxy, address, err := startProxy(ctx, config)
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "HTTP/SOCKS5 proxy ready at", address)
	if _, err = control.Write([]byte("R")); err != nil {
		return errors.Join(err, proxy.Close())
	}
	err = serveChecks(ctx, control, commands)
	fmt.Fprintln(os.Stderr, "Proxy stopping")
	return errors.Join(err, proxy.Close())
}

func serveChecks(ctx context.Context, control io.Writer, commands <-chan byte) error {
	results := make(chan error, 1)
	var cancelCheck context.CancelFunc
	for {
		select {
		case <-ctx.Done():
			return nil
		case command := <-commands:
			switch command {
			case 'H', 'D':
				if cancelCheck != nil {
					return errors.New("received a second test while a test was running")
				}
				checkCtx, cancel := context.WithCancel(ctx)
				cancelCheck = cancel
				go func() {
					results <- runNetworkCheck(checkCtx, command)
				}()
			case 'C':
				if cancelCheck != nil {
					cancelCheck()
				}
			default:
				return errors.New("unknown panel command")
			}
		case err := <-results:
			cancelCheck()
			cancelCheck = nil
			reply := byte('P')
			if err != nil {
				reply = 'F'
				if !errors.Is(err, context.Canceled) {
					fmt.Fprintln(os.Stderr, "FAIL:", err)
				}
			}
			if _, err := control.Write([]byte{reply}); err != nil {
				return err
			}
		}
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) != 1 || args[0] != "managed" {
		return errors.New("expected managed mode")
	}
	const controlFD = 3
	if err := syscall.SetNonblock(controlFD, true); err != nil {
		return fmt.Errorf("open panel control: %w", err)
	}
	control := os.NewFile(controlFD, "panel-control")
	defer control.Close()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	commands := make(chan byte, 1)
	go func() {
		defer cancel()
		var command [1]byte
		for {
			if _, err := io.ReadFull(control, command[:]); err != nil {
				return
			}
			select {
			case commands <- command[0]:
			case <-ctx.Done():
				return
			}
		}
	}()
	return managedProxy(ctx, control, commands)
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	fmt.Fprintln(os.Stderr, "PS5 Network 0.21 · core", C.Version, "·", runtime.Version())
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
}
