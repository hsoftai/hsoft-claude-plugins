package broker

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"time"
)

// DefaultVmnetIP is the host side of the Cowork vmnet bridge (the VM's gateway).
// The host binds the Plan A listener here and advertises it as the dial address.
const DefaultVmnetIP = "172.16.10.1"

// ServerConfig configures the host-side broker for one session.
type ServerConfig struct {
	Session     string
	Spool       string // shared `outputs` mount (host path)
	VmnetIP     string // bind/advertise IP for Plan A (default DefaultVmnetIP)
	Port        int
	TokenB64    string        // capability token (base64) published in the bootstrap
	TTL         time.Duration // bootstrap lifetime
	IdleTimeout time.Duration // shut down after this much inactivity
	Handler     *Handler      // resolving authority (Token must match TokenB64)
}

// RunServer brings up the broker for one session and blocks until it goes idle.
// It tries Plan A (bind on the vmnet IP, VM dials in); if the bind is refused it
// falls back to Plan B (advertise a port, poll the spool rendezvous, and dial the
// VM's listener). Either way the host plays the protocol-server role.
func RunServer(cfg ServerConfig) error {
	if cfg.VmnetIP == "" {
		cfg.VmnetIP = DefaultVmnetIP
	}
	// Never bind all interfaces: the broker must be reachable only on the vmnet
	// bridge (or loopback in tests), never the internet-facing interface.
	if cfg.VmnetIP == "0.0.0.0" || cfg.VmnetIP == "::" {
		return fmt.Errorf("broker refuses to bind all interfaces (%q); set broker_host to the vmnet bridge IP", cfg.VmnetIP)
	}
	if cfg.TTL == 0 {
		cfg.TTL = 1 * time.Hour
	}
	// Clean up the control-plane file when the broker exits so a stale bootstrap
	// (with a now-dead token) does not linger in the spool. The token is also
	// rotated every start, so any leftover file's token is already invalid.
	defer RemoveBootstrap(cfg.Spool, cfg.Session)
	defer RemoveRendezvous(cfg.Spool, cfg.Session)

	tlsCfg, fp, err := newServerTLS()
	if err != nil {
		return err
	}

	// Plan A: bind on the vmnet interface; the VM dials in.
	if ln, lerr := tls.Listen("tcp", fmtAddr(cfg.VmnetIP, cfg.Port), tlsCfg); lerr == nil {
		defer ln.Close()
		tcpAddr, ok := ln.Addr().(*net.TCPAddr)
		if !ok {
			return fmt.Errorf("unexpected listener address type")
		}
		bs := Bootstrap{
			Session: cfg.Session, Plan: "A",
			DialAddr: fmtAddr(cfg.VmnetIP, tcpAddr.Port), TokenB64: cfg.TokenB64,
			CertFP: fp, TTLUnix: time.Now().Add(cfg.TTL).Unix(),
		}
		if err := WriteBootstrap(cfg.Spool, bs); err != nil {
			return err
		}
		return cfg.acceptLoop(ln, bs)
	}

	// Plan B: cannot bind reachably; advertise a port and dial the VM instead.
	bs := Bootstrap{
		Session: cfg.Session, Plan: "B", Port: cfg.Port,
		TokenB64: cfg.TokenB64, TTLUnix: time.Now().Add(cfg.TTL).Unix(),
	}
	if err := WriteBootstrap(cfg.Spool, bs); err != nil {
		return err
	}
	return cfg.dialLoop(bs)
}

func (cfg ServerConfig) idle() time.Duration {
	if cfg.IdleTimeout > 0 {
		return cfg.IdleTimeout
	}
	return 30 * time.Minute
}

// acceptLoop (Plan A) serves dialed-in clients one at a time until idle, keeping
// the bootstrap's TTL refreshed while the broker is alive.
func (cfg ServerConfig) acceptLoop(ln net.Listener, bs Bootstrap) error {
	idle := cfg.idle()
	timer := time.AfterFunc(idle, func() { _ = ln.Close() })
	defer timer.Stop()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return nil // listener closed by idle timer
		}
		timer.Reset(idle)
		_ = cfg.Handler.serve(conn) // sequential: one broker, low volume
		cfg.refresh(&bs)
	}
}

// dialLoop (Plan B) polls the spool for the VM's rendezvous and dials its
// listener (cert pinned) to serve a resolve request.
func (cfg ServerConfig) dialLoop(bs Bootstrap) error {
	idle := cfg.idle()
	deadline := time.Now().Add(idle)
	var last int64
	for time.Now().Before(deadline) {
		if r, err := readRendezvous(cfg.Spool, cfg.Session); err == nil && r.Stamp != last && r.Addr != "" && r.CertFP != "" {
			last = r.Stamp
			// The rendezvous Addr is VM-controlled; only dial an address on the
			// vmnet bridge subnet so the VM cannot steer the host into connecting
			// to an arbitrary internal service (SSRF / port-scan primitive).
			if onBridgeSubnet(cfg.VmnetIP, r.Addr) {
				if conn, derr := tls.Dial("tcp", r.Addr, pinnedClientTLS(r.CertFP)); derr == nil {
					_ = cfg.Handler.serve(conn)
					deadline = time.Now().Add(idle)
					cfg.refresh(&bs)
				}
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return nil
}

// onBridgeSubnet reports whether addr (host:port) is in the same /24 as the
// vmnet bridge IP — the only network the host should dial in Plan B. Loopback is
// allowed so tests can drive Plan B on 127.0.0.1.
func onBridgeSubnet(vmnetIP, addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	bridge := net.ParseIP(vmnetIP)
	if bridge == nil {
		return false
	}
	a, b := ip.To4(), bridge.To4()
	if a == nil || b == nil {
		return false
	}
	return a[0] == b[0] && a[1] == b[1] && a[2] == b[2] // same /24
}

// refresh re-publishes the bootstrap with an extended TTL while the broker lives,
// so the advisory TTL can stay short without expiring during a long session.
func (cfg ServerConfig) refresh(bs *Bootstrap) {
	bs.TTLUnix = time.Now().Add(cfg.TTL).Unix()
	_ = WriteBootstrap(cfg.Spool, *bs)
}

// Client is the VM-side value consumer. It is created from a discovered Bootstrap.
type Client struct {
	Bootstrap Bootstrap
	Spool     string // spool the bootstrap came from (used for Plan B rendezvous)
	ExecID    string
}

// Resolve asks the host broker for the values of refs and returns ref->value. It
// tries Plan A (dial the host) first and falls back to Plan B (listen, let the
// host dial in) when the bootstrap allows. Values exist only in memory here.
func (c Client) Resolve(refs []string) (map[string]string, error) {
	if len(refs) == 0 {
		return map[string]string{}, nil
	}
	token := c.Bootstrap.Token()
	if len(token) < minTokenLen {
		return nil, fmt.Errorf("capability token too short")
	}
	if c.ExecID == "" {
		c.ExecID, _ = NewExecID()
	}

	if c.Bootstrap.DialAddr != "" { // Plan A
		if c.Bootstrap.CertFP == "" {
			return nil, fmt.Errorf("broker bootstrap has no certificate pin (refusing to connect)")
		}
		conn, err := tls.Dial("tcp", c.Bootstrap.DialAddr, pinnedClientTLS(c.Bootstrap.CertFP))
		if err == nil {
			defer conn.Close()
			return request(conn, token, c.ExecID, refs)
		}
		if c.Bootstrap.Plan != "B" && c.Bootstrap.Port == 0 {
			return nil, fmt.Errorf("broker unreachable at %s: %w", c.Bootstrap.DialAddr, err)
		}
		// else fall through to Plan B
	}
	return c.resolveViaListen(token, refs)
}

// resolveViaListen (Plan B) opens a TLS listener, announces it via the spool, and
// waits for the host broker to dial in and answer the resolve request.
func (c Client) resolveViaListen(token []byte, refs []string) (map[string]string, error) {
	port := c.Bootstrap.Port
	if port == 0 {
		return nil, fmt.Errorf("no Plan B port advertised by the broker")
	}
	tlsCfg, fp, err := newServerTLS()
	if err != nil {
		return nil, err
	}
	// Bind the specific bridge address, not all interfaces, to limit exposure.
	ip := localIP()
	if ip == "" || ip == "0.0.0.0" {
		return nil, fmt.Errorf("no bridge IP to bind the Plan B listener (refusing all-interfaces)")
	}
	ln, err := tls.Listen("tcp", fmtAddr(ip, port), tlsCfg)
	if err != nil {
		return nil, err
	}
	defer ln.Close()

	if err := writeRendezvous(c.Spool, rendezvous{
		Session: c.Bootstrap.Session, Addr: fmtAddr(ip, port), CertFP: fp, Stamp: time.Now().UnixNano(),
	}); err != nil {
		return nil, err
	}

	type res struct {
		v map[string]string
		e error
	}
	ch := make(chan res, 1)
	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			ch <- res{nil, aerr}
			return
		}
		defer conn.Close()
		v, e := request(conn, token, c.ExecID, refs)
		ch <- res{v, e}
	}()
	select {
	case r := <-ch:
		return r.v, r.e
	case <-time.After(handshakeTimeout):
		return nil, fmt.Errorf("timed out waiting for the host broker to dial in (Plan B)")
	}
}

// NewExecID returns a short random execution id, included in requests for audit
// correlation only (it is not a security boundary).
func NewExecID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// localIP returns the host's first non-loopback IPv4 (the VM's bridge address in
// Cowork), used to tell the host broker where to dial in Plan B. It is a var so
// tests can pin it to loopback.
var localIP = func() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "0.0.0.0"
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLoopback() {
			if v4 := ipn.IP.To4(); v4 != nil {
				return v4.String()
			}
		}
	}
	return "0.0.0.0"
}
