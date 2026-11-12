package ikev2

import (
	"encoding/binary"
	"net"
	"sync"
	"time"

	"github.com/free5gc/ike/message"
)

// Limits for answers to messages received outside any IKE SA (RFC 7296
// section 2.21.4: "A node needs to limit the rate at which it will send
// messages in response to unprotected messages").
const (
	invalidSPIPerSource = time.Second // at most one answer per source address in this interval
	invalidSPIPerSecond = 50          // and this many per second in total
	invalidSPIMaxTrack  = 4096        // source addresses remembered
)

type invalidSPILimiter struct {
	mu     sync.Mutex
	last   map[string]time.Time
	window time.Time
	count  int
}

func (l *invalidSPILimiter) allow(src net.IP, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.window) >= time.Second {
		l.window, l.count = now, 0
	}
	if l.count >= invalidSPIPerSecond {
		return false
	}
	if l.last == nil {
		l.last = make(map[string]time.Time)
	}
	key := src.String()
	if t, ok := l.last[key]; ok && now.Sub(t) < invalidSPIPerSource {
		return false
	}
	if len(l.last) >= invalidSPIMaxTrack {
		for k, t := range l.last {
			if now.Sub(t) >= invalidSPIPerSource {
				delete(l.last, k)
			}
		}
		if len(l.last) >= invalidSPIMaxTrack {
			return false
		}
	}
	l.last[key] = now
	l.count++
	return true
}

// sendInvalidIKESPI answers a request that belongs to no IKE SA known to us,
// typically because the ePDG restarted or the half-open SA expired while the
// UE was unreachable. The response is not protected, goes back to where the
// request came from, and copies the SPIs and the Message ID (RFC 7296 section
// 2.21.4). It lets the UE notice at once that the SA is gone instead of
// retransmitting into silence. Responses are never answered.
func (s *Server) sendInvalidIKESPI(conn *net.UDPConn, remote *net.UDPAddr, hdr *message.IKEHeader) {
	if conn == nil || remote == nil || hdr.Flags&message.ResponseBitCheck != 0 {
		return
	}
	if !s.invalidSPI.allow(remote.IP, time.Now()) {
		return
	}
	const notifyLen = 8
	out := make([]byte, message.IKE_HEADER_LEN+notifyLen)
	binary.BigEndian.PutUint64(out[0:], hdr.InitiatorSPI)
	binary.BigEndian.PutUint64(out[8:], hdr.ResponderSPI)
	out[16] = uint8(message.TypeN)
	out[17] = 2 << 4 // IKEv2
	out[18] = hdr.ExchangeType
	out[19] = message.ResponseBitCheck // response, sent by the original responder
	binary.BigEndian.PutUint32(out[20:], hdr.MessageID)
	binary.BigEndian.PutUint32(out[24:], uint32(len(out)))
	n := out[message.IKE_HEADER_LEN:]
	// Notify payload: no next payload, not critical, no protocol, no SPI.
	binary.BigEndian.PutUint16(n[2:], notifyLen)
	binary.BigEndian.PutUint16(n[6:], message.INVALID_IKE_SPI)
	s.send(conn, remote, out, conn == s.conn4500)
	s.log.Info("INVALID_IKE_SPI sent", "spi_i", hdr.InitiatorSPI, "exchange", hdr.ExchangeType, "remote", remote)
}
