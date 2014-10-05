package sniproxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
)

type SNIProxy struct {
	ln       net.Listener
	conf     *tls.Config
	proxyMap map[string]string
}

func NewSNIProxy() *SNIProxy {
	s := SNIProxy{}

	s.conf = &tls.Config{}
	s.conf.NextProtos = []string{"http/1.1"}

	s.proxyMap = map[string]string{}

	return &s
}

func (s *SNIProxy) AddCert(certPath, keyPath, origin string) error {
	certs, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return err
	}
	x509Cert, err := x509.ParseCertificate(certs.Certificate[0])
	if err != nil {
		return err
	}
	s.proxyMap[x509Cert.Subject.CommonName] = origin
	s.conf.Certificates = append(s.conf.Certificates, certs)
	s.conf.BuildNameToCertificate()
	return nil
}

func (s *SNIProxy) Listen(network, laddr string) error {
	l, err := net.Listen(network, laddr)
	if err != nil {
		return err
	}
	s.ln = l
	return nil
}

func (s *SNIProxy) Serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			println(err)
			continue
		}
		tcpconn, ok := c.(*net.TCPConn)
		if !ok {
			println("not tcp conn")
			continue
		}
		go s.Process(tcpconn)
	}
}

func (s *SNIProxy) Process(c *net.TCPConn) error {
	tlsconn := tls.Server(c, s.conf)
	tlsconn.Handshake()
	serverName := tlsconn.ConnectionState().ServerName
	origin, ok := s.proxyMap[serverName]
	if !ok {
		tlsconn.Close()
		return fmt.Errorf("origin not found for %s", serverName)
	}
	p := newProxier(c, tlsconn, origin)
	p.Connect()
	p.Proxy()
	return nil
}

type proxier struct {
	clientTCP *net.TCPConn
	clientTLS *tls.Conn

	originTCP *net.TCPConn
	origin    string
}

func newProxier(tcpconn *net.TCPConn, tlsconn *tls.Conn, origin string) *proxier {
	p := &proxier{
		clientTCP: tcpconn,
		clientTLS: tlsconn,
		origin:    origin,
	}
	return p
}

func (p *proxier) Connect() error {
	conn, err := net.Dial("tcp", p.origin)
	if err != nil {
		return err
	}
	p.originTCP = conn.(*net.TCPConn)
	return nil
}

func (p *proxier) Proxy() error {
	go p.client2origin()
	go p.origin2client()
	return nil
}

func (p *proxier) client2origin() error {
	defer p.originTCP.CloseWrite()
	defer p.clientTCP.CloseRead()
	io.Copy(p.originTCP, p.clientTLS)
	return nil
}

func (p *proxier) origin2client() error {
	defer p.clientTCP.CloseWrite()
	defer p.clientTCP.CloseRead()
	io.Copy(p.clientTLS, p.originTCP)
	return nil
}
