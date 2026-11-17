// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/sagernet/sing-box/common/certificate"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
)

const checkURL = "https://api.ipify.org/"
const checkTimeout = 12 * time.Second

func runNetworkCheck(ctx context.Context, mode byte) error {
	proxyAddress := fmt.Sprintf("127.0.0.1:%d", proxyPort)
	store, err := certificate.NewStore(ctx, logger.NOP(), option.CertificateOptions{Store: "mozilla"})
	if err != nil {
		return err
	}
	if mode == 'D' {
		return checkDownload(ctx, proxyAddress, store.Pool())
	}
	return checkHTTPS(ctx, proxyAddress, checkURL, store.Pool())
}

func checkHTTPS(ctx context.Context, proxyAddress, target string, roots *x509.CertPool) error {
	var failures []error
	for _, scheme := range []string{"http", "socks5h"} {
		fmt.Fprintln(os.Stderr, "Checking HTTPS via", scheme)
		ip, err := check(ctx, proxyAddress, scheme, target, roots)
		if err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", scheme, err))
			continue
		}
		fmt.Fprintln(os.Stderr, "PASS:", scheme, "· public IP", ip)
	}
	return errors.Join(failures...)
}

func check(ctx context.Context, proxyAddress, scheme, target string, roots *x509.CertPool) (netip.Addr, error) {
	transport := proxyTransport(proxyAddress, scheme, roots)
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   checkTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return netip.Addr{}, err
	}
	response, err := client.Do(request)
	if err != nil {
		return netip.Addr{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return netip.Addr{}, fmt.Errorf("unexpected HTTP status %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 65))
	if err != nil {
		return netip.Addr{}, err
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(string(body)))
	if len(body) > 64 || err != nil || !ip.Is4() {
		return netip.Addr{}, errors.New("expected an IPv4 address in the HTTPS response")
	}
	return ip, nil
}

func proxyTransport(address, scheme string, roots *x509.CertPool) *http.Transport {
	proxyURL := &url.URL{Scheme: scheme, Host: address}
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	return &http.Transport{
		Proxy:             http.ProxyURL(proxyURL),
		DialContext:       dialer.DialContext,
		TLSClientConfig:   &tls.Config{RootCAs: roots},
		DisableKeepAlives: true,
	}
}
