package ikev2

import (
	"net"
	"testing"

	"github.com/free5gc/ike/message"

	"vectorcore-epdg/internal/config"
	"vectorcore-epdg/internal/pco"
)

func attrTypes(cp *message.Configuration) map[uint16][]net.IP {
	out := map[uint16][]net.IP{}
	for _, a := range cp.ConfigurationAttribute {
		out[a.Type] = append(out[a.Type], net.IP(a.Value))
	}
	return out
}

func TestAppendPrivatePCSCF(t *testing.T) {
	dec := &pco.Decoded{
		PCSCFv4: []net.IP{net.ParseIP("10.46.0.10")},
		PCSCFv6: []net.IP{net.ParseIP("2001:db8::10")},
	}
	cfg := config.PCOConfig{RequestPCSCFv4: true, RequestPCSCFv6: true}

	cp := &message.Configuration{ConfigurationType: message.CFG_REPLY}
	appendPrivatePCSCF(cp, dec, cfg, false, false)
	if len(cp.ConfigurationAttribute) != 0 {
		t.Fatalf("not requested: got %d attributes, want 0", len(cp.ConfigurationAttribute))
	}

	cp = &message.Configuration{ConfigurationType: message.CFG_REPLY}
	appendPrivatePCSCF(cp, dec, cfg, true, true)
	got := attrTypes(cp)
	if len(got[cfgPrivatePCSCF4]) != 1 || !got[cfgPrivatePCSCF4][0].Equal(net.ParseIP("10.46.0.10")) || len(got[cfgPrivatePCSCF4][0]) != 4 {
		t.Fatalf("16389 = %v, want 10.46.0.10 as 4 bytes", got[cfgPrivatePCSCF4])
	}
	if len(got[cfgPrivatePCSCF6]) != 1 || !got[cfgPrivatePCSCF6][0].Equal(net.ParseIP("2001:db8::10")) {
		t.Fatalf("16390 = %v, want 2001:db8::10", got[cfgPrivatePCSCF6])
	}

	cp = &message.Configuration{ConfigurationType: message.CFG_REPLY}
	appendPrivatePCSCF(cp, dec, config.PCOConfig{}, true, true)
	if len(cp.ConfigurationAttribute) != 0 {
		t.Fatal("P-CSCF not requested from the PGW: private attributes must stay empty")
	}
}
