package ikev2

import (
	"net"
	"testing"
	"time"
)

func TestInvalidSPILimiterPerSA(t *testing.T) {
	var l invalidSPILimiter
	now := time.Unix(1000, 0)
	a, b := net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2")
	if !l.allow(a, 1, now) {
		t.Fatal("first answer for an SA must be allowed")
	}
	if l.allow(a, 1, now.Add(invalidSPIPerSA/2)) {
		t.Fatal("second answer for the same SA inside the interval must be refused")
	}
	if !l.allow(a, 2, now.Add(invalidSPIPerSA/2)) {
		t.Fatal("another UE behind the same address must get its own answer")
	}
	if !l.allow(b, 1, now.Add(invalidSPIPerSA/2)) {
		t.Fatal("another source must not be affected")
	}
	if !l.allow(a, 1, now.Add(invalidSPIPerSA)) {
		t.Fatal("the SA must be answered again after the interval")
	}
}

func TestInvalidSPILimiterTotal(t *testing.T) {
	var l invalidSPILimiter
	now := time.Unix(2000, 0)
	allowed := 0
	for i := 0; i < invalidSPIPerSecond*2; i++ {
		if l.allow(net.IPv4(10, 0, byte(i>>8), byte(i)), 1, now) {
			allowed++
		}
	}
	if allowed != invalidSPIPerSecond {
		t.Fatalf("allowed %d answers in one second, want %d", allowed, invalidSPIPerSecond)
	}
	if !l.allow(net.IPv4(10, 1, 0, 1), 1, now.Add(time.Second)) {
		t.Fatal("the total limit must reset after a second")
	}
}
