// SPDX-License-Identifier: MIT

package main

import (
	"context"
	stdtls "crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
	"golang.org/x/net/http2"
)

func registerNaiveH2(registry *outbound.Registry) {
	outbound.Register[option.NaiveOutboundOptions](registry, C.TypeNaive, newNaiveH2)
}

type naiveH2 struct {
	outbound.Adapter
	ctx       context.Context
	logger    log.ContextLogger
	server    M.Socksaddr
	headers   http.Header
	transport *http2.Transport
	uot       *uot.Client
}

func newNaiveH2(ctx context.Context, _ adapter.Router, logger log.ContextLogger, tag string, opts option.NaiveOutboundOptions) (adapter.Outbound, error) {
	if opts.QUIC || opts.QUICCongestionControl != "" || opts.QUICSessionReceiveWindow != nil {
		return nil, errors.New("this Naive client supports HTTP/2 only (quic=false)")
	}
	if opts.InsecureConcurrency != 0 || opts.ReceiveWindow != nil {
		return nil, errors.New("custom Naive connection count and receive window require Cronet")
	}
	if opts.TLS == nil || !opts.TLS.Enabled || opts.TLS.Insecure || opts.TLS.DisableSNI {
		return nil, errors.New("Naive HTTP/2 requires TLS with server verification")
	}
	if len(opts.TLS.ALPN) != 0 {
		return nil, errors.New("Naive HTTP/2 sets ALPN to h2")
	}
	if strings.Contains(opts.Username, ":") {
		return nil, errors.New("Naive username cannot contain a colon")
	}
	server := opts.ServerOptions.Build()
	if !server.IsValid() || server.Port == 0 {
		return nil, errors.New("Naive server and port are required")
	}
	baseDialer, err := dialer.NewWithOptions(dialer.Options{
		Context:          ctx,
		Options:          opts.DialerOptions,
		RemoteIsDomain:   server.IsDomain(),
		ResolverOnDetour: true,
		NewDialer:        true,
	})
	if err != nil {
		return nil, err
	}
	tlsConfig, err := tls.NewClient(ctx, logger, server.AddrString(), *opts.TLS)
	if err != nil {
		return nil, err
	}
	tlsConfig.SetNextProtos([]string{http2.NextProtoTLS})
	tlsDialer := tls.NewDialer(baseDialer, tlsConfig)

	headers := opts.ExtraHeaders.Build().Clone()
	if headers == nil {
		headers = make(http.Header)
	}
	if headers.Get("User-Agent") == "" {
		headers.Set("User-Agent", "")
	}
	if opts.Username != "" || opts.Password != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(opts.Username + ":" + opts.Password))
		headers.Set("Proxy-Authorization", "Basic "+auth)
	}
	client := &naiveH2{
		ctx:     ctx,
		logger:  logger,
		server:  server,
		headers: headers,
		transport: &http2.Transport{
			DisableCompression: true,
			IdleConnTimeout:    90 * time.Second,
			ReadIdleTimeout:    45 * time.Second,
			PingTimeout:        10 * time.Second,
			WriteByteTimeout:   30 * time.Second,
			DialTLSContext: func(ctx context.Context, _, _ string, _ *stdtls.Config) (net.Conn, error) {
				conn, err := tlsDialer.DialTLSContext(adapter.ContextForMultiplexSession(ctx), server)
				if err != nil {
					return nil, err
				}
				if conn.ConnectionState().NegotiatedProtocol != http2.NextProtoTLS {
					conn.Close()
					return nil, errors.New("Naive server did not negotiate HTTP/2 over TLS")
				}
				return conn, nil
			},
		},
	}
	networks := []string{N.NetworkTCP}
	if opts.UDPOverTCP != nil && opts.UDPOverTCP.Enabled {
		version := opts.UDPOverTCP.Version
		if version != 0 && version != uot.Version && version != uot.LegacyVersion {
			return nil, errors.New("unsupported Naive UDP over TCP version")
		}
		client.uot = &uot.Client{Dialer: client, Version: version}
		networks = append(networks, N.NetworkUDP)
	}
	client.Adapter = outbound.NewAdapterWithDialerOptions(C.TypeNaive, tag, networks, opts.DialerOptions)
	return client, nil
}

func (c *naiveH2) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage == adapter.StartStateInitialize {
		c.ctx = scope.Context()
		scope.Add(func() error {
			c.transport.CloseIdleConnections()
			return nil
		})
	}
	return nil
}

func (c *naiveH2) MultiplexEnabled() bool { return true }

func (c *naiveH2) InterfaceUpdated(context.Context) { c.transport.CloseIdleConnections() }

func (c *naiveH2) DialContext(ctx context.Context, network string, dst M.Socksaddr) (net.Conn, error) {
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		return c.dialStream(ctx, dst)
	case N.NetworkUDP:
		if c.uot != nil {
			return c.uot.DialContext(ctx, network, dst)
		}
	}
	return nil, fmt.Errorf("Naive HTTP/2 does not support network %q with this profile", network)
}

func (c *naiveH2) ListenPacket(ctx context.Context, dst M.Socksaddr) (net.PacketConn, error) {
	if c.uot == nil {
		return nil, errors.New("Naive UDP over TCP is disabled")
	}
	return c.uot.ListenPacket(ctx, dst)
}

func (c *naiveH2) dialStream(ctx context.Context, dst M.Socksaddr) (net.Conn, error) {
	if !dst.IsValid() {
		return nil, errors.New("invalid Naive CONNECT destination")
	}
	streamCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	stopShutdown := context.AfterFunc(c.ctx, cancel)
	stopDial := context.AfterFunc(ctx, cancel)
	timeout := time.AfterFunc(C.TCPTimeout, cancel)
	closeStream := func() {
		stopShutdown()
		cancel()
	}

	upload, writer := io.Pipe()
	req := (&http.Request{
		Method:        http.MethodConnect,
		URL:           &url.URL{Scheme: "https", Host: c.server.String()},
		Host:          dst.String(),
		Header:        c.headers.Clone(),
		Body:          upload,
		ContentLength: -1,
	}).WithContext(streamCtx)
	req.Header.Set("Padding", naivePaddingHeader())
	resp, err := c.transport.RoundTrip(req)
	expired := !timeout.Stop()
	stopDial()
	if err == nil && expired {
		err = context.DeadlineExceeded
	}
	if err == nil && resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("proxy returned HTTP %d", resp.StatusCode)
	}
	if err == nil {
		err = streamCtx.Err()
	}
	if err != nil {
		closeStream()
		upload.Close()
		writer.Close()
		if resp != nil {
			resp.Body.Close()
		}
		if expired && errors.Is(err, context.Canceled) {
			err = context.DeadlineExceeded
		}
		return nil, fmt.Errorf("Naive HTTP/2 CONNECT: %w", err)
	}
	padded := resp.Header.Get("Padding") != ""
	c.logger.DebugContext(ctx, "HTTP/2 CONNECT accepted (padding=", padded, ")")
	return &naiveStream{
		reader: resp.Body, writer: writer, cancel: closeStream,
		remote: dst, padded: padded,
	}, nil
}

func naivePaddingHeader() string {
	const symbols = "!#$()+<>?@[]^`{}"
	padding := make([]byte, 30+rand.IntN(32))
	for i := range padding {
		if i < 16 {
			padding[i] = symbols[rand.IntN(len(symbols))]
		} else {
			padding[i] = '~'
		}
	}
	return string(padding)
}
