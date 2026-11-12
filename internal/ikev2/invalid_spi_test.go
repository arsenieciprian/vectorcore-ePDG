package ikev2

import (
	"net"
	"testing"
	"time"
)

func TestInvalidSPILimiterPerSource(t *testing.T) {
	var l invalidSPILimiter
	now := time.Unix(1000, 0)
	a, b := net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2")
	if !l.allow(a, now) {
		t.Fatal("first answer to a source must be allowed")
	}
	if l.allow(a, now.Add(invalidSPIPerSource/2)) {
		t.Fatal("second answer to the same source inside the interval must be refused")
	}
	if !l.allow(b, now.Add(invalidSPIPerSource/2)) {
		t.Fatal("another source must not be affected")
	}
	if !l.allow(a, now.Add(invalidSPIPerSource)) {
		t.Fatal("the source must be answered again after the interval")
	}
}

func TestInvalidSPILimiterTotal(t *testing.T) {
	var l invalidSPILimiter
	now := time.Unix(2000, 0)
	allowed := 0
	for i := 0; i < invalidSPIPerSecond*2; i++ {
		if l.allow(net.IPv4(10, 0, byte(i>>8), byte(i)), now) {
			allowed++
		}
	}
	if allowed != invalidSPIPerSecond {
		t.Fatalf("allowed %d answers in one second, want %d", allowed, invalidSPIPerSecond)
	}
	if !l.allow(net.IPv4(10, 1, 0, 1), now.Add(time.Second)) {
		t.Fatal("the total limit must reset after a second")
	}
}
