// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"encoding/binary"
	"io"
	"math/rand/v2"
	"net"
	"os"
	"sync"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

// See the NaiveProxy padding specification. The first eight frames per
// direction are length-prefixed, after which this is a plain byte stream.
const naivePaddedFrames = 8
const naiveMaxFrame = 65535

type naiveStream struct {
	reader io.ReadCloser
	writer *io.PipeWriter
	cancel func()
	remote M.Socksaddr
	padded bool

	readMu    sync.Mutex
	reads     int
	dataLeft  int
	padding   int
	writeMu   sync.Mutex
	writes    int
	closeOnce sync.Once
	closeErr  error
}

func (s *naiveStream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	s.readMu.Lock()
	defer s.readMu.Unlock()
	if s.padded {
		for {
			if s.dataLeft != 0 {
				n, err := s.reader.Read(p[:min(len(p), s.dataLeft)])
				s.dataLeft -= n
				return n, err
			}
			if s.padding != 0 {
				if _, err := io.CopyN(io.Discard, s.reader, int64(s.padding)); err != nil {
					return 0, err
				}
				s.padding = 0
			}
			if s.reads == naivePaddedFrames {
				break
			}
			var header [3]byte
			if _, err := io.ReadFull(s.reader, header[:]); err != nil {
				return 0, err
			}
			s.dataLeft = int(binary.BigEndian.Uint16(header[:2]))
			s.padding = int(header[2])
			s.reads++
		}
	}
	return s.reader.Read(p)
}

func (s *naiveStream) Write(p []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	written := 0
	for len(p) != 0 && s.padded && s.writes < naivePaddedFrames {
		size := min(len(p), naiveMaxFrame)
		padding := rand.IntN(256)
		frame := make([]byte, 3+size+padding)
		binary.BigEndian.PutUint16(frame[:2], uint16(size))
		frame[2] = byte(padding)
		copy(frame[3:], p[:size])
		n, err := s.writer.Write(frame)
		if err != nil {
			s.cancel()
			return written + max(0, min(n-3, size)), err
		}
		written += size
		p = p[size:]
		s.writes++
	}
	if len(p) == 0 {
		return written, nil
	}
	n, err := s.writer.Write(p)
	return written + n, err
}

func (s *naiveStream) CloseWrite() error { return s.writer.Close() }

func (s *naiveStream) Close() error {
	s.closeOnce.Do(func() {
		s.cancel()
		s.writer.CloseWithError(net.ErrClosed)
		s.closeErr = s.reader.Close()
	})
	return s.closeErr
}

func (s *naiveStream) LocalAddr() net.Addr              { return M.Socksaddr{} }
func (s *naiveStream) RemoteAddr() net.Addr             { return s.remote }
func (s *naiveStream) SetDeadline(time.Time) error      { return os.ErrInvalid }
func (s *naiveStream) SetReadDeadline(time.Time) error  { return os.ErrInvalid }
func (s *naiveStream) SetWriteDeadline(time.Time) error { return os.ErrInvalid }
func (s *naiveStream) NeedAdditionalReadDeadline() bool { return true }

var _ net.Conn = (*naiveStream)(nil)
