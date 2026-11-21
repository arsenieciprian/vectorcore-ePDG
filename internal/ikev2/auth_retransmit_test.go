package ikev2

// RFC 7296 §2.1: the responder must answer a retransmitted IKE_AUTH request
// with the response it already sent. Seen on a lossy 4G link (21.11.2026):
// a retransmitted EAP response was relayed to the AAA as a new round (EAP
// failure → AUTHENTICATION_FAILED), and a retransmitted final AUTH got no
// answer at all ("SA not in auth state"), leaving the UE stuck.

import (
	"bytes"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/free5gc/ike/message"
)

func retransmitTestSetup(t *testing.T) (*Server, *net.UDPConn, *net.UDPConn, *ikeSA) {
	t.Helper()
	srv := NewServer(&Config{ListenAddr: "127.0.0.1"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	srvConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { srvConn.Close() })
	ueConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ueConn.Close() })

	key := randomKey(t, encrAesCbc256.KeyLen())
	integKey := randomKey(t, integSha256_128.KeyLen())
	saKey := &ikeSAKey{encr: encrAesCbc256, integ: integSha256_128, SK_er: key, SK_ei: key, SK_ar: integKey, SK_ai: integKey}
	sa := &ikeSA{saKey: saKey, spiI: 0x1111, spiR: 0x2222, state: ikeStateAuth}
	srv.storeSA(sa)
	return srv, srvConn, ueConn, sa
}

// ueRequest builds an encrypted IKE_AUTH request from the UE (Initiator flag set).
func ueRequest(t *testing.T, sa *ikeSA, msgID uint32, plain []byte) ([]byte, *message.IKEHeader) {
	t.Helper()
	totalLen, err := encryptedSKMessageLen(sa.saKey, len(plain))
	if err != nil {
		t.Fatalf("encryptedSKMessageLen: %v", err)
	}
	hdrBytes := buildIKEHeaderBytes(sa.spiI, sa.spiR, message.IKE_AUTH, msgID, totalLen)
	hdrBytes[19] = message.InitiatorBitCheck
	pkt, err := encryptSK(sa.saKey, 0, plain, hdrBytes)
	if err != nil {
		t.Fatalf("encryptSK: %v", err)
	}
	hdr := &message.IKEHeader{InitiatorSPI: sa.spiI, ResponderSPI: sa.spiR, ExchangeType: message.IKE_AUTH,
		Flags: message.InitiatorBitCheck, MessageID: binary.BigEndian.Uint32(pkt[20:24])}
	return pkt, hdr
}

func readUE(t *testing.T, ueConn *net.UDPConn) []byte {
	t.Helper()
	buf := make([]byte, 4096)
	_ = ueConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := ueConn.Read(buf)
	if err != nil {
		t.Fatalf("UE did not receive a response: %v", err)
	}
	return buf[:n]
}

// The final IKE_AUTH response was lost: the SA is already established when the
// UE retransmits its AUTH request; it must get the same response again.
func TestIKEAuthRetransmissionAfterEstablishedResendsCachedResponse(t *testing.T) {
	srv, srvConn, ueConn, sa := retransmitTestSetup(t)
	ueAddr := ueConn.LocalAddr().(*net.UDPAddr)

	if err := srv.sendEncryptedRaw(srvConn, ueAddr, sa, message.IKE_AUTH, 3, 0, []byte("final IKE_AUTH response"), false); err != nil {
		t.Fatalf("sendEncryptedRaw: %v", err)
	}
	first := readUE(t, ueConn) // the response the UE "lost"
	sa.state = ikeStateEstablished

	pkt, hdr := ueRequest(t, sa, 3, []byte("AUTH request"))
	srv.handleIKEAuth(srvConn, ueAddr, pkt, hdr, false)

	if again := readUE(t, ueConn); !bytes.Equal(again, first) {
		t.Fatalf("retransmitted response differs from the original (%d vs %d bytes)", len(again), len(first))
	}
}

// A retransmitted EAP response must not start a new EAP round (no SWm
// exchange: srv.swm is nil here, a new round would panic).
func TestIKEAuthRetransmittedEAPResponseNotProcessedAgain(t *testing.T) {
	srv, srvConn, ueConn, sa := retransmitTestSetup(t)
	ueAddr := ueConn.LocalAddr().(*net.UDPAddr)
	sa.eapRound = 2

	if err := srv.sendEncryptedRaw(srvConn, ueAddr, sa, message.IKE_AUTH, 2, 0, []byte("EAP-Success"), false); err != nil {
		t.Fatalf("sendEncryptedRaw: %v", err)
	}
	first := readUE(t, ueConn)

	pkt, hdr := ueRequest(t, sa, 2, []byte("EAP response"))
	srv.handleIKEAuth(srvConn, ueAddr, pkt, hdr, false)

	if again := readUE(t, ueConn); !bytes.Equal(again, first) {
		t.Fatal("retransmitted EAP response did not get the cached response")
	}
	if sa.eapRound != 2 {
		t.Fatalf("eapRound = %d, want 2 (retransmission processed as a new round)", sa.eapRound)
	}
}

// A packet with the cached message ID but a bad ICV is dropped, not answered.
func TestIKEAuthRetransmissionWithBadIntegrityDropped(t *testing.T) {
	srv, srvConn, ueConn, sa := retransmitTestSetup(t)
	ueAddr := ueConn.LocalAddr().(*net.UDPAddr)

	if err := srv.sendEncryptedRaw(srvConn, ueAddr, sa, message.IKE_AUTH, 3, 0, []byte("final"), false); err != nil {
		t.Fatalf("sendEncryptedRaw: %v", err)
	}
	readUE(t, ueConn)

	pkt, hdr := ueRequest(t, sa, 3, []byte("AUTH request"))
	pkt[len(pkt)-1] ^= 0xff
	srv.handleIKEAuth(srvConn, ueAddr, pkt, hdr, false)

	buf := make([]byte, 4096)
	_ = ueConn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := ueConn.Read(buf); err == nil {
		t.Fatal("a tampered retransmission was answered")
	}
}
