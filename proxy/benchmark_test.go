package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
)

func BenchmarkCopyData(b *testing.B) {
	proxy := proxyForTest(nil, nil)

	for i := range 16 {
		b.Run(fmt.Sprintf("%d bytes", 1<<i), func(b *testing.B) {
			benchmarkCopyData(b, proxy, 1<<i)
		})
	}
}

// BenchmarkCopyDataBufferSize is BenchmarkCopyData at bulk transfer sizes
// (32 KiB, 256 KiB, 1 MiB) for each copy buffer size, with a sink that reads
// 1 MiB at a time so the pipe never bounds the chunk the copy loop moves.
// Note net.Pipe is synchronous, so this measures the loop's own overhead
// per chunk, not the syscall cost a socket has; BenchmarkBulkThroughput
// measures that.
func BenchmarkCopyDataBufferSize(b *testing.B) {
	for _, bufSize := range []int{32 << 10, 64 << 10, 128 << 10, 256 << 10} {
		for _, size := range []int{32 << 10, 256 << 10, 1 << 20} {
			b.Run(fmt.Sprintf("buf=%dK/transfer=%dK", bufSize>>10, size>>10), func(b *testing.B) {
				proxy := proxyForTest(nil, nil)
				proxy.CopyBufferSize = bufSize
				b.SetBytes(int64(size))
				benchmarkCopyDataSink(b, proxy, size, 1<<20)
			})
		}
	}
}

func benchmarkCopyData(b *testing.B, proxy *Proxy, size int) {
	benchmarkCopyDataSink(b, proxy, size, 1<<10)
}

func benchmarkCopyDataSink(b *testing.B, proxy *Proxy, size, sinkSize int) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		srcIn, srcOut := net.Pipe()
		dstIn, dstOut := net.Pipe()
		defer func() {
			srcIn.Close()
			srcOut.Close()
			dstIn.Close()
			dstOut.Close()
		}()

		go func() {
			buf := make([]byte, size)
			for i := range size {
				buf[i] = byte(i % (1 << 8))
			}
			_, _ = srcIn.Write(buf)
			srcIn.Close()
		}()

		go func() {
			var err error
			buf := make([]byte, sinkSize)
			for err == nil {
				_, err = dstOut.Read(buf)
			}
			if err != nil && err != io.EOF && !isClosedConnectionError(err) {
				fmt.Fprintf(os.Stderr, "%v\n", err)
			}
		}()

		proxy.copyData(dstIn, srcOut)
	}
}

// benchTCPConn is a net.Conn stub whose addresses are *net.TCPAddr, so
// proxyProtoHeader exercises the real TCPv4 transportProtocol branch rather
// than falling through to UNSPEC.
type benchTCPConn struct {
	net.Conn
}

func (benchTCPConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 51000}
}

func (benchTCPConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 443}
}

// BenchmarkProxyProtoHeader measures construction of the PROXY protocol v2
// header on the accept hot path (proxyProtoHeader in proxy.go). It runs
// once per connection when a PROXY-protocol mode is enabled, and reports the
// allocations that construction performs. TLSFull additionally copies the peer
// cert DER, so it is benchmarked separately from TLS mode.
func BenchmarkProxyProtoHeader(b *testing.B) {
	_, leaf := benchSelfSignedCert(b)
	conn := benchTCPConn{}

	state := &tls.ConnectionState{
		Version:            tls.VersionTLS13,
		CipherSuite:        tls.TLS_AES_128_GCM_SHA256,
		NegotiatedProtocol: "h2",
		ServerName:         "example.com",
		PeerCertificates:   []*x509.Certificate{leaf},
	}

	for _, tc := range []struct {
		name string
		mode ProxyProtocolMode
	}{
		{"conn", ProxyProtocolConn},
		{"tls", ProxyProtocolTLS},
		{"tls-full", ProxyProtocolTLSFull},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, _ = proxyProtoHeader(conn, state, tc.mode)
			}
		})
	}
}
