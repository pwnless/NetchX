package main

import "C"

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

const (
	typeReset = iota
	typeList
	typeListen
	typeChinaDNS
	typeOtherDNS
)

type upstream struct {
	client  *dns.Client
	address string
}

type configuration struct {
	path     string
	listen   string
	chinaDNS upstream
	otherDNS upstream
}

var state struct {
	sync.Mutex
	configuration
	tcpSocket net.Listener
	udpSocket net.PacketConn
}

//export aiodns_dial
func aiodns_dial(name C.int, value *C.char) bool {
	if value == nil {
		return false
	}

	return dial(int(name), C.GoString(value))
}

func dial(name int, value string) bool {
	state.Lock()
	defer state.Unlock()

	// A running service keeps the configuration that it was started with.
	// Call aiodns_free before dialing a replacement configuration.
	if state.tcpSocket != nil || state.udpSocket != nil {
		return false
	}

	switch name {
	case typeReset:
		state.configuration = configuration{}
	case typeList:
		state.path = value
	case typeListen:
		if _, _, err := net.SplitHostPort(value); err != nil {
			return false
		}
		state.listen = value
	case typeChinaDNS:
		endpoint, ok := parseUpstream(value)
		if !ok {
			return false
		}
		state.chinaDNS = endpoint
	case typeOtherDNS:
		endpoint, ok := parseUpstream(value)
		if !ok {
			return false
		}
		state.otherDNS = endpoint
	default:
		return false
	}

	return true
}

func parseUpstream(value string) (upstream, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return upstream{}, false
	}

	if !strings.Contains(value, "://") {
		if address, err := netip.ParseAddr(value); err == nil {
			value = "tcp://" + net.JoinHostPort(address.String(), "53")
		} else {
			value = "tcp://" + value
		}
	}

	parsed, err := url.Parse(value)
	if err != nil || parsed == nil || parsed.Host == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return upstream{}, false
	}

	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "tcp" && scheme != "tls" {
		return upstream{}, false
	}

	host := parsed.Hostname()
	if host == "" {
		return upstream{}, false
	}

	port := parsed.Port()
	if port == "" {
		port = "53"
	}
	parsedPort, err := strconv.ParseUint(port, 10, 16)
	if err != nil || parsedPort == 0 {
		return upstream{}, false
	}

	client := dns.Client{Net: "tcp"}
	if scheme == "tls" {
		client.Net = "tcp-tls"
		client.TLSConfig = &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	}

	return upstream{client: &client, address: net.JoinHostPort(host, port)}, true
}

//export aiodns_init
func aiodns_init() bool {
	return initialize()
}

func initialize() bool {
	state.Lock()
	defer state.Unlock()

	if state.tcpSocket != nil || state.udpSocket != nil || state.listen == "" ||
		state.chinaDNS.address == "" || state.otherDNS.address == "" {
		return false
	}

	mux, ok := createMux(&state.configuration)
	if !ok {
		return false
	}

	tcpSocket, err := net.Listen("tcp", state.listen)
	if err != nil {
		fmt.Printf("[aiodns][init] net.Listen: %v\n", err)
		return false
	}

	udpSocket, err := net.ListenPacket("udp", state.listen)
	if err != nil {
		_ = tcpSocket.Close()
		fmt.Printf("[aiodns][init] net.ListenPacket: %v\n", err)
		return false
	}

	state.tcpSocket = tcpSocket
	state.udpSocket = udpSocket

	go serveTCP(tcpSocket, mux)
	go serveUDP(udpSocket, mux)
	fmt.Println("[aiodns] Started")
	return true
}

func createMux(config *configuration) (*dns.ServeMux, bool) {
	mux := dns.NewServeMux()

	if config.path != "" {
		file, err := os.Open(config.path)
		if err != nil {
			fmt.Printf("[aiodns][init] os.Open: %v\n", err)
			return nil, false
		}
		defer file.Close()

		scan := bufio.NewScanner(file)
		for scan.Scan() {
			domain := strings.TrimSpace(scan.Text())
			if domain != "" {
				mux.HandleFunc(dns.Fqdn(domain), proxyHandler(config.chinaDNS))
			}
		}
		if err := scan.Err(); err != nil {
			fmt.Printf("[aiodns][init] read rule list: %v\n", err)
			return nil, false
		}
	}

	mux.HandleFunc("in-addr.arpa.", handleServerName)
	mux.HandleFunc(".", proxyHandler(config.otherDNS))
	return mux, true
}

func serveTCP(listener net.Listener, mux dns.Handler) {
	if err := (&dns.Server{Listener: listener, Net: "tcp", Handler: mux}).ActivateAndServe(); err != nil {
		if !isClosedNetworkError(err) {
			fmt.Printf("[aiodns][tcp] serve: %v\n", err)
		}
	}
}

func serveUDP(connection net.PacketConn, mux dns.Handler) {
	if err := (&dns.Server{PacketConn: connection, Net: "udp", Handler: mux}).ActivateAndServe(); err != nil {
		if !isClosedNetworkError(err) {
			fmt.Printf("[aiodns][udp] serve: %v\n", err)
		}
	}
}

func isClosedNetworkError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "use of closed network connection")
}

//export aiodns_free
func aiodns_free() {
	shutdown()
}

func shutdown() {
	state.Lock()
	tcpSocket := state.tcpSocket
	udpSocket := state.udpSocket
	state.tcpSocket = nil
	state.udpSocket = nil
	state.Unlock()

	if tcpSocket != nil {
		_ = tcpSocket.Close()
	}
	if udpSocket != nil {
		_ = udpSocket.Close()
	}
}

func handleServerName(w dns.ResponseWriter, message *dns.Msg) {
	reply := new(dns.Msg)
	reply.SetReply(message)

	for _, question := range message.Question {
		record, err := dns.NewRR(fmt.Sprintf("%s PTR NetchX", question.Name))
		if err != nil {
			reply.Rcode = dns.RcodeServerFailure
			break
		}
		reply.Answer = append(reply.Answer, record)
	}

	_ = w.WriteMsg(reply)
}

func proxyHandler(endpoint upstream) dns.HandlerFunc {
	return func(w dns.ResponseWriter, message *dns.Msg) {
		if endpoint.client == nil {
			failure := new(dns.Msg)
			failure.SetReply(message)
			failure.Rcode = dns.RcodeServerFailure
			_ = w.WriteMsg(failure)
			return
		}

		reply, _, err := endpoint.client.Exchange(message, endpoint.address)
		if err != nil || reply == nil {
			if err != nil {
				fmt.Printf("[aiodns] proxy %s: %v\n", endpoint.address, err)
			}
			failure := new(dns.Msg)
			failure.SetReply(message)
			failure.Rcode = dns.RcodeServerFailure
			_ = w.WriteMsg(failure)
			return
		}

		_ = w.WriteMsg(reply)
	}
}

func main() {}
