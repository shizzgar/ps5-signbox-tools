// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"
)

const downloadURLPath = "/data/ps5-local-proxy/download-url.txt"
const controlDownloadURL = "https://speed.cloudflare.com/__down?bytes=4194304"
const controlBytes = 4 * 1024 * 1024
const sampleBytes = 1024 * 1024
const maxURLBytes = 8192
const downloadTimeout = 25 * time.Second

func checkDownload(ctx context.Context, proxy string, roots *x509.CertPool) error {
	target, sample, err := downloadTarget(downloadURLPath)
	if err != nil {
		return err
	}
	transport := proxyTransport(proxy, "http", roots)
	defer transport.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(ctx, downloadTimeout)
	defer cancel()
	return probeDownload(ctx, transport, target, sample)
}

func downloadTarget(path string) (*url.URL, bool, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if errors.Is(err, os.ErrNotExist) {
		control, err := url.Parse(controlDownloadURL)
		return control, false, err
	}
	if err != nil {
		return nil, false, fmt.Errorf("open %s: %w", path, err)
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, false, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxURLBytes {
		return nil, false, errors.New("download-url.txt must be a regular file up to 8192 bytes")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxURLBytes+1))
	if err != nil {
		return nil, false, err
	}
	raw := strings.TrimSpace(string(data))
	target, err := url.Parse(raw)
	if len(data) > maxURLBytes || strings.ContainsAny(raw, " \t\r\n") || err != nil || !validDownloadTarget(target) {
		return nil, false, errors.New("download-url.txt must contain one HTTPS URL without user information")
	}
	return target, true, nil
}

func validDownloadTarget(target *url.URL) bool {
	return target.Scheme == "https" && target.Hostname() != "" && target.User == nil
}

func probeDownload(ctx context.Context, transport http.RoundTripper, target *url.URL, sample bool) error {
	limit := int64(controlBytes)
	if sample {
		limit = sampleBytes
	}
	fmt.Fprintf(os.Stderr, "GET %s via HTTP CONNECT · up to %d bytes\n", target.Hostname(), limit)
	start := time.Now()
	response, err := requestDownload(ctx, transport, target, sample)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	mediaType, _, _ := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if mediaType == "" {
		mediaType = "unknown"
	}
	fmt.Fprintf(os.Stderr, "HTTP %d · %s · headers after %.2fs\n", response.StatusCode, mediaType, time.Since(start).Seconds())
	if response.StatusCode != http.StatusOK && !(sample && response.StatusCode == http.StatusPartialContent) {
		return fmt.Errorf("server returned HTTP %d", response.StatusCode)
	}
	if mediaType == "text/html" || mediaType == "application/xhtml+xml" {
		return errors.New("the server sent an HTML page in place of a file response")
	}
	rangeLength := int64(0)
	if response.StatusCode == http.StatusPartialContent {
		var first, last int64
		fields, err := fmt.Sscanf(response.Header.Get("Content-Range"), "bytes %d-%d/", &first, &last)
		if err != nil || fields != 2 || first != 0 || last < 0 || last >= limit {
			return errors.New("HTTP 206 did not describe a valid initial byte range")
		}
		rangeLength = last + 1
	}

	readLimit := limit
	if !sample {
		readLimit++
	}
	bodyStart := time.Now()
	n, err := io.Copy(io.Discard, io.LimitReader(response.Body, readLimit))
	elapsed := max(time.Since(bodyStart).Seconds(), 0.000001)
	fmt.Fprintf(os.Stderr, "Received %d bytes in %.2fs (%.2f MiB/s)\n", n, elapsed, float64(n)/(1024*1024*elapsed))
	if err != nil {
		return fmt.Errorf("reading download after %d bytes: %w", n, err)
	}
	if sample {
		if n == 0 {
			return errors.New("empty download response")
		}
		if rangeLength != 0 && n != rangeLength {
			return fmt.Errorf("HTTP range announced %d bytes, received %d", rangeLength, n)
		}
		fmt.Fprintln(os.Stderr, "PASS: received a sample from the supplied URL")
	} else {
		if n != limit {
			return fmt.Errorf("expected %d bytes from the download test, received %d", limit, n)
		}
		fmt.Fprintln(os.Stderr, "PASS: received the complete 4 MiB test response")
	}
	return nil
}

func requestDownload(ctx context.Context, transport http.RoundTripper, target *url.URL, sample bool) (*http.Response, error) {
	for redirects := 0; ; redirects++ {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
		if err != nil {
			return nil, errors.New("cannot create the HTTPS request")
		}
		request.Header.Set("Accept-Encoding", "identity")
		if sample {
			request.Header.Set("Range", "bytes=0-1048575")
		}
		response, err := transport.RoundTrip(request)
		if err != nil {
			return nil, fmt.Errorf("request to %s before HTTP response: %w", target.Hostname(), err)
		}
		switch response.StatusCode {
		case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
			next, err := response.Location()
			response.Body.Close()
			if err != nil || !validDownloadTarget(next) {
				return nil, fmt.Errorf("HTTP %d from %s without a usable HTTPS redirect", response.StatusCode, target.Hostname())
			}
			if redirects >= 4 {
				return nil, errors.New("too many download redirects")
			}
			fmt.Fprintln(os.Stderr, "Redirect to", next.Hostname())
			target = next
		default:
			return response, nil
		}
	}
}
