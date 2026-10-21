package main

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestParseUpstream(t *testing.T) {
	tests := []struct {
		input   string
		address string
		network string
		ok      bool
	}{
		{"tcp://1.1.1.1:53", "1.1.1.1:53", "tcp", true},
		{"tls://[2606:4700:4700::1111]:853", "[2606:4700:4700::1111]:853", "tcp-tls", true},
		{"1.1.1.1", "1.1.1.1:53", "tcp", true},
		{"2606:4700:4700::1111", "[2606:4700:4700::1111]:53", "tcp", true},
		{"https://dns.example.test", "", "", false},
		{"tcp://dns.example.test/path", "", "", false},
		{"tcp://dns.example.test:0", "", "", false},
	}

	for _, test := range tests {
		endpoint, ok := parseUpstream(test.input)
		if ok != test.ok {
			t.Fatalf("parseUpstream(%q) success = %v, want %v", test.input, ok, test.ok)
		}
		if !ok {
			continue
		}
		if endpoint.address != test.address || endpoint.client.Net != test.network {
			t.Fatalf("parseUpstream(%q) = (%q, %q), want (%q, %q)", test.input, endpoint.address, endpoint.client.Net, test.address, test.network)
		}
	}
}

func TestAioDNSLifecycleServesDNS(t *testing.T) {
	shutdown()
	defer shutdown()

	upstreamAddress, stopUpstream := startUpstream(t)
	defer stopUpstream()

	listenAddress := reserveAddress(t)
	if !dial(typeReset, "") || !dial(typeListen, listenAddress) ||
		!dial(typeChinaDNS, "tcp://"+upstreamAddress) || !dial(typeOtherDNS, "tcp://"+upstreamAddress) {
		t.Fatal("could not configure AioDNS")
	}
	if !initialize() {
		t.Fatal("could not start AioDNS")
	}

	client := dns.Client{Net: "udp", Timeout: 2 * time.Second}
	query := new(dns.Msg)
	query.SetQuestion("example.test.", dns.TypeA)
	reply, _, err := client.Exchange(query, listenAddress)
	if err != nil {
		t.Fatalf("proxy DNS query failed: %v", err)
	}
	if len(reply.Answer) != 1 || reply.Answer[0].Header().Rrtype != dns.TypeA {
		t.Fatalf("unexpected proxied answer: %#v", reply.Answer)
	}

	ptrQuery := new(dns.Msg)
	ptrQuery.SetQuestion("1.0.0.127.in-addr.arpa.", dns.TypePTR)
	ptrReply, _, err := client.Exchange(ptrQuery, listenAddress)
	if err != nil {
		t.Fatalf("PTR DNS query failed: %v", err)
	}
	if len(ptrReply.Answer) != 1 || ptrReply.Answer[0].Header().Rrtype != dns.TypePTR {
		t.Fatalf("unexpected PTR answer: %#v", ptrReply.Answer)
	}
}

func reserveAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test listener: %v", err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	return address
}

func startUpstream(t *testing.T) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start test upstream listener: %v", err)
	}

	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, request *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(request)
		for _, question := range request.Question {
			if question.Qtype == dns.TypeA {
				reply.Answer = append(reply.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
					A:   net.ParseIP("203.0.113.10"),
				})
			}
		}
		_ = w.WriteMsg(reply)
	})

	server := &dns.Server{Listener: listener, Net: "tcp", Handler: mux}
	go func() {
		if err := server.ActivateAndServe(); err != nil && !isClosedNetworkError(err) {
			t.Errorf("test upstream failed: %v", err)
		}
	}()

	return listener.Addr().String(), func() {
		if err := server.Shutdown(); err != nil {
			t.Errorf("stop test upstream: %v", err)
		}
	}
}
