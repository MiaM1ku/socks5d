package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
)

const (
	socksVersion = uint8(5)

	authNoAuth       = uint8(0)
	authUserPassword = uint8(2)
	authNoAcceptable = uint8(255)

	authVersion = uint8(1)
	authSuccess = uint8(0)
	authFailure = uint8(1)

	commandConnect      = uint8(1)
	commandBind         = uint8(2)
	commandUDPAssociate = uint8(3)

	addressIPv4   = uint8(1)
	addressDomain = uint8(3)
	addressIPv6   = uint8(4)

	replySucceeded           = uint8(0)
	replyServerFailure       = uint8(1)
	replyNetworkUnreachable  = uint8(3)
	replyHostUnreachable     = uint8(4)
	replyConnectionRefused   = uint8(5)
	replyCommandNotSupported = uint8(7)
	replyAddressUnsupported  = uint8(8)
)

type Server struct {
	listenAddr string
	username   string
	password   string
	logger     *log.Logger
}

type request struct {
	command uint8
	dest    addrSpec
}

type addrSpec struct {
	host string
	ip   net.IP
	port int
}

type udpAssociation struct {
	clientIP   net.IP
	clientPort int
}

func NewServer(listenAddr, username, password string) *Server {
	return &Server{
		listenAddr: listenAddr,
		username:   username,
		password:   password,
		logger:     log.New(os.Stdout, "", log.LstdFlags),
	}
}

func (a addrSpec) address() string {
	if a.host != "" {
		return net.JoinHostPort(a.host, strconv.Itoa(a.port))
	}
	return net.JoinHostPort(a.ip.String(), strconv.Itoa(a.port))
}

func NewAddrSpecFromTCP(addr *net.TCPAddr) addrSpec {
	return addrSpec{ip: addr.IP, port: addr.Port}
}

func NewAddrSpecFromUDP(addr *net.UDPAddr) addrSpec {
	return addrSpec{ip: addr.IP, port: addr.Port}
}

func (s *Server) ListenAndServe() error {
	listeners, err := s.listenAll()
	if err != nil {
		return err
	}
	errCh := make(chan error, len(listeners))
	for _, listener := range listeners {
		l := listener
		go func() {
			errCh <- s.Serve(l)
		}()
	}

	err = <-errCh
	for _, listener := range listeners {
		_ = listener.Close()
	}
	return err
}

func (s *Server) listenAll() ([]net.Listener, error) {
	host, port, err := net.SplitHostPort(s.listenAddr)
	if err != nil {
		return nil, err
	}

	// For wildcard addresses, try enabling both families explicitly.
	if host == "" || host == "0.0.0.0" {
		var listeners []net.Listener
		if l6, l6Err := net.Listen("tcp6", net.JoinHostPort("::", port)); l6Err == nil {
			listeners = append(listeners, l6)
		}
		if l4, l4Err := net.Listen("tcp4", net.JoinHostPort("0.0.0.0", port)); l4Err == nil {
			listeners = append(listeners, l4)
		}
		if len(listeners) > 0 {
			return listeners, nil
		}
	}

	listener, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return nil, err
	}
	return []net.Listener{listener}, nil
}

func (s *Server) Serve(listener net.Listener) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go s.serveConn(conn)
	}
}

func (s *Server) serveConn(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	if err := s.authenticate(conn, reader); err != nil {
		s.logger.Printf("[ERR] socks: %v", err)
		return
	}

	req, err := readRequest(reader)
	if err != nil {
		reply := replyServerFailure
		if errors.Is(err, errAddressUnsupported) {
			reply = replyAddressUnsupported
		}
		_ = writeReply(conn, reply, addrSpec{})
		s.logger.Printf("[ERR] socks: %v", err)
		return
	}

	switch req.command {
	case commandConnect:
		err = s.handleConnect(conn, reader, req)
	case commandBind:
		_ = writeReply(conn, replyCommandNotSupported, addrSpec{})
		err = fmt.Errorf("bind is not supported")
	case commandUDPAssociate:
		err = s.handleUDPAssociate(conn, reader, req)
	default:
		_ = writeReply(conn, replyCommandNotSupported, addrSpec{})
		err = fmt.Errorf("unsupported command: %d", req.command)
	}

	if err != nil {
		s.logger.Printf("[ERR] socks: %v", err)
	}
}

func (s *Server) authenticate(conn io.Writer, reader io.Reader) error {
	header := []byte{0, 0}
	if _, err := io.ReadFull(reader, header); err != nil {
		return fmt.Errorf("failed to read auth header: %w", err)
	}
	if header[0] != socksVersion {
		return fmt.Errorf("unsupported SOCKS version: %d", header[0])
	}

	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(reader, methods); err != nil {
		return fmt.Errorf("failed to read auth methods: %w", err)
	}

	method := authNoAcceptable
	if s.username == "" {
		if containsMethod(methods, authNoAuth) {
			method = authNoAuth
		}
	} else if containsMethod(methods, authUserPassword) {
		method = authUserPassword
	}

	if _, err := conn.Write([]byte{socksVersion, method}); err != nil {
		return fmt.Errorf("failed to write auth method: %w", err)
	}
	if method == authNoAcceptable {
		return fmt.Errorf("no supported authentication mechanism")
	}
	if method == authNoAuth {
		return nil
	}

	return s.verifyUserPassword(conn, reader)
}

func (s *Server) verifyUserPassword(conn io.Writer, reader io.Reader) error {
	header := []byte{0, 0}
	if _, err := io.ReadFull(reader, header); err != nil {
		return fmt.Errorf("failed to read user auth header: %w", err)
	}
	if header[0] != authVersion {
		return fmt.Errorf("unsupported auth version: %d", header[0])
	}

	username := make([]byte, int(header[1]))
	if _, err := io.ReadFull(reader, username); err != nil {
		return fmt.Errorf("failed to read username: %w", err)
	}

	if _, err := io.ReadFull(reader, header[:1]); err != nil {
		return fmt.Errorf("failed to read password length: %w", err)
	}

	password := make([]byte, int(header[0]))
	if _, err := io.ReadFull(reader, password); err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

	status := authFailure
	if string(username) == s.username && string(password) == s.password {
		status = authSuccess
	}
	if _, err := conn.Write([]byte{authVersion, status}); err != nil {
		return fmt.Errorf("failed to write auth result: %w", err)
	}
	if status != authSuccess {
		return fmt.Errorf("user authentication failed")
	}
	return nil
}

func (s *Server) handleConnect(conn net.Conn, reader *bufio.Reader, req *request) error {
	target, err := net.Dial("tcp", req.dest.address())
	if err != nil {
		reply := replyFromError(err)
		_ = writeReply(conn, reply, addrSpec{})
		return fmt.Errorf("connect to %s failed: %w", req.dest.address(), err)
	}
	defer target.Close()

	if err := writeReply(conn, replySucceeded, NewAddrSpecFromTCP(target.LocalAddr().(*net.TCPAddr))); err != nil {
		return fmt.Errorf("failed to write connect reply: %w", err)
	}

	errCh := make(chan error, 2)
	go proxy(target, reader, errCh)
	go proxy(conn, target, errCh)

	var result error
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil && !errors.Is(err, io.EOF) && !isClosedError(err) && result == nil {
			result = err
		}
	}
	return result
}

func (s *Server) handleUDPAssociate(conn net.Conn, reader *bufio.Reader, req *request) error {
	clientTCPAddr, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		_ = writeReply(conn, replyServerFailure, addrSpec{})
		return fmt.Errorf("unexpected remote address type: %T", conn.RemoteAddr())
	}

	bindIP := net.IP(nil)
	if localTCPAddr, ok := conn.LocalAddr().(*net.TCPAddr); ok && localTCPAddr.IP != nil && !localTCPAddr.IP.IsUnspecified() {
		bindIP = localTCPAddr.IP
	}

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: bindIP, Port: 0})
	if err != nil {
		_ = writeReply(conn, replyServerFailure, addrSpec{})
		return fmt.Errorf("failed to listen for UDP association: %w", err)
	}
	defer udpConn.Close()

	replyAddr := NewAddrSpecFromUDP(udpConn.LocalAddr().(*net.UDPAddr))
	if bindIP != nil {
		replyAddr.ip = bindIP
	}
	if err := writeReply(conn, replySucceeded, replyAddr); err != nil {
		return fmt.Errorf("failed to write UDP associate reply: %w", err)
	}

	assoc := &udpAssociation{clientIP: clientTCPAddr.IP}
	if req.dest.port != 0 {
		assoc.clientPort = req.dest.port
	}

	errCh := make(chan error, 2)
	go func() {
		_, copyErr := io.Copy(io.Discard, reader)
		if copyErr != nil && !errors.Is(copyErr, io.EOF) && !isClosedError(copyErr) {
			errCh <- copyErr
			return
		}
		_ = udpConn.Close()
		errCh <- nil
	}()
	go func() {
		errCh <- s.serveUDPAssociation(udpConn, assoc)
	}()

	var result error
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil && !isClosedError(err) && result == nil {
			result = err
		}
	}
	return result
}

func (s *Server) serveUDPAssociation(conn *net.UDPConn, assoc *udpAssociation) error {
	buf := make([]byte, 64*1024)
	for {
		n, peer, err := conn.ReadFromUDP(buf)
		if err != nil {
			if isClosedError(err) {
				return nil
			}
			return err
		}

		if assoc.matchesClient(peer) {
			dest, payload, parseErr := parseUDPPacket(buf[:n])
			if parseErr != nil {
				continue
			}

			target, resolveErr := net.ResolveUDPAddr("udp", dest.address())
			if resolveErr != nil {
				continue
			}
			if _, writeErr := conn.WriteToUDP(payload, target); writeErr != nil {
				return writeErr
			}
			continue
		}

		clientAddr, ok := assoc.clientAddr()
		if !ok {
			continue
		}

		packet, buildErr := buildUDPPacket(NewAddrSpecFromUDP(peer), buf[:n])
		if buildErr != nil {
			continue
		}
		if _, writeErr := conn.WriteToUDP(packet, clientAddr); writeErr != nil {
			return writeErr
		}
	}
}

func (a *udpAssociation) matchesClient(addr *net.UDPAddr) bool {
	if a.clientIP == nil || !addr.IP.Equal(a.clientIP) {
		return false
	}
	if a.clientPort == 0 {
		a.clientPort = addr.Port
	}
	return a.clientPort == addr.Port
}

func (a *udpAssociation) clientAddr() (*net.UDPAddr, bool) {
	if a.clientIP == nil || a.clientPort == 0 {
		return nil, false
	}
	return &net.UDPAddr{IP: a.clientIP, Port: a.clientPort}, true
}

func readRequest(reader io.Reader) (*request, error) {
	header := []byte{0, 0, 0}
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, fmt.Errorf("failed to read request header: %w", err)
	}
	if header[0] != socksVersion {
		return nil, fmt.Errorf("unsupported request version: %d", header[0])
	}
	if header[2] != 0 {
		return nil, fmt.Errorf("invalid request reserved byte: %d", header[2])
	}

	dest, err := readAddrSpec(reader)
	if err != nil {
		return nil, err
	}

	return &request{command: header[1], dest: dest}, nil
}

var errAddressUnsupported = errors.New("address type not supported")

func readAddrSpec(reader io.Reader) (addrSpec, error) {
	typeBuf := []byte{0}
	if _, err := io.ReadFull(reader, typeBuf); err != nil {
		return addrSpec{}, fmt.Errorf("failed to read address type: %w", err)
	}

	addr := addrSpec{}
	switch typeBuf[0] {
	case addressIPv4:
		buf := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(reader, buf); err != nil {
			return addrSpec{}, fmt.Errorf("failed to read IPv4 address: %w", err)
		}
		addr.ip = net.IP(buf)
	case addressIPv6:
		buf := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(reader, buf); err != nil {
			return addrSpec{}, fmt.Errorf("failed to read IPv6 address: %w", err)
		}
		addr.ip = net.IP(buf)
	case addressDomain:
		if _, err := io.ReadFull(reader, typeBuf); err != nil {
			return addrSpec{}, fmt.Errorf("failed to read domain length: %w", err)
		}
		buf := make([]byte, int(typeBuf[0]))
		if _, err := io.ReadFull(reader, buf); err != nil {
			return addrSpec{}, fmt.Errorf("failed to read domain: %w", err)
		}
		addr.host = string(buf)
	default:
		return addrSpec{}, errAddressUnsupported
	}

	portBuf := []byte{0, 0}
	if _, err := io.ReadFull(reader, portBuf); err != nil {
		return addrSpec{}, fmt.Errorf("failed to read port: %w", err)
	}
	addr.port = int(portBuf[0])<<8 | int(portBuf[1])
	return addr, nil
}

func writeReply(writer io.Writer, reply uint8, addr addrSpec) error {
	var body []byte
	switch {
	case addr.host != "":
		if len(addr.host) > 255 {
			return fmt.Errorf("reply domain is too long")
		}
		body = append(body, addressDomain, byte(len(addr.host)))
		body = append(body, addr.host...)
	case addr.ip != nil && addr.ip.To4() != nil:
		body = append(body, addressIPv4)
		body = append(body, addr.ip.To4()...)
	case addr.ip != nil && addr.ip.To16() != nil:
		body = append(body, addressIPv6)
		body = append(body, addr.ip.To16()...)
	default:
		body = append(body, addressIPv4, 0, 0, 0, 0)
	}

	body = append(body, byte(addr.port>>8), byte(addr.port))
	msg := append([]byte{socksVersion, reply, 0}, body...)
	_, err := writer.Write(msg)
	return err
}

func parseUDPPacket(packet []byte) (addrSpec, []byte, error) {
	if len(packet) < 4 {
		return addrSpec{}, nil, io.ErrUnexpectedEOF
	}
	if packet[0] != 0 || packet[1] != 0 {
		return addrSpec{}, nil, fmt.Errorf("invalid UDP reserved header")
	}
	if packet[2] != 0 {
		return addrSpec{}, nil, fmt.Errorf("fragmented UDP packets are not supported")
	}

	reader := bytes.NewReader(packet[3:])
	dest, err := readAddrSpec(reader)
	if err != nil {
		return addrSpec{}, nil, err
	}
	offset := len(packet[3:]) - reader.Len()
	return dest, packet[3+offset:], nil
}

func buildUDPPacket(addr addrSpec, payload []byte) ([]byte, error) {
	buf := bytes.NewBuffer([]byte{0, 0, 0})

	switch {
	case addr.host != "":
		if len(addr.host) > 255 {
			return nil, fmt.Errorf("domain is too long")
		}
		buf.WriteByte(addressDomain)
		buf.WriteByte(byte(len(addr.host)))
		buf.WriteString(addr.host)
	case addr.ip != nil && addr.ip.To4() != nil:
		buf.WriteByte(addressIPv4)
		buf.Write(addr.ip.To4())
	case addr.ip != nil && addr.ip.To16() != nil:
		buf.WriteByte(addressIPv6)
		buf.Write(addr.ip.To16())
	default:
		return nil, fmt.Errorf("unsupported UDP address")
	}

	buf.WriteByte(byte(addr.port >> 8))
	buf.WriteByte(byte(addr.port))
	buf.Write(payload)
	return buf.Bytes(), nil
}

type closeWriter interface {
	CloseWrite() error
}

func proxy(dst io.Writer, src io.Reader, errCh chan<- error) {
	buf := make([]byte, 32*1024)
	var err error
	for {
		nr, readErr := src.Read(buf)
		if nr > 0 {
			written := 0
			for written < nr {
				nw, writeErr := dst.Write(buf[written:nr])
				if nw > 0 {
					written += nw
				}
				if writeErr != nil {
					err = writeErr
					break
				}
				if nw == 0 {
					err = io.ErrShortWrite
					break
				}
			}
			if err != nil {
				break
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				err = nil
			} else {
				err = readErr
			}
			break
		}
	}

	if conn, ok := dst.(closeWriter); ok {
		_ = conn.CloseWrite()
	}
	errCh <- err
}

func containsMethod(methods []byte, want byte) bool {
	for _, method := range methods {
		if method == want {
			return true
		}
	}
	return false
}

func replyFromError(err error) uint8 {
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "refused"):
		return replyConnectionRefused
	case strings.Contains(msg, "network is unreachable"):
		return replyNetworkUnreachable
	case strings.Contains(msg, "no such host"), strings.Contains(msg, "host is down"):
		return replyHostUnreachable
	default:
		return replyHostUnreachable
	}
}

func isClosedError(err error) bool {
	return errors.Is(err, net.ErrClosed) || strings.Contains(err.Error(), "use of closed network connection")
}
