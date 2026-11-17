// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"
)

const defaultProxy = "http://127.0.0.1:17890"
const ipCheckURL = "https://api.ipify.org/"

func main() {
	if err := run(os.Args[1:]); err != nil && !errors.Is(err, flag.ErrHelp) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprintln(os.Stderr, "Usage: network-check {ip|download} [options]")
		fmt.Fprintln(os.Stderr, "Run a command with -h for its options.")
		return flag.ErrHelp
	}
	var timeout time.Duration
	switch args[0] {
	case "ip":
		timeout = 12 * time.Second
	case "download":
		timeout = 25 * time.Second
	default:
		return errors.New("expected the ip or download command")
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	proxy := flags.String("proxy", defaultProxy, "HTTP or SOCKS5 proxy URL with an explicit port")
	var urlFile string
	if args[0] == "download" {
		flags.StringVar(&urlFile, "url-file", "", "file with one HTTPS URL to sample")
	}
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional argument")
	}
	transport, err := proxyTransport(*proxy)
	if err != nil {
		return err
	}
	defer transport.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if args[0] == "ip" {
		return checkIP(ctx, transport)
	}
	target, sample, err := downloadTarget(urlFile)
	if err != nil {
		return err
	}
	return probeDownload(ctx, transport, target, sample)
}

func proxyTransport(address string) (*http.Transport, error) {
	proxy, err := url.Parse(address)
	if err != nil || proxy.Hostname() == "" || proxy.Port() == "" ||
		proxy.User != nil || proxy.Path != "" || proxy.RawQuery != "" || proxy.Fragment != "" ||
		(proxy.Scheme != "http" && proxy.Scheme != "socks5" && proxy.Scheme != "socks5h") {
		return nil, errors.New("proxy must be an http://, socks5:// or socks5h:// URL with a host and port")
	}
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	return &http.Transport{
		Proxy:             http.ProxyURL(proxy),
		DialContext:       dialer.DialContext,
		DisableKeepAlives: true,
	}, nil
}

func checkIP(ctx context.Context, transport http.RoundTripper) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, ipCheckURL, nil)
	if err != nil {
		return err
	}
	response, err := transport.RoundTrip(request)
	if err != nil {
		return fmt.Errorf("HTTPS IP check: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("IP check received HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 65))
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(string(body)))
	if len(body) > 64 || err != nil || ip.Zone() != "" {
		return errors.New("expected an IP address in the HTTPS response")
	}
	fmt.Println(ip)
	return nil
}
