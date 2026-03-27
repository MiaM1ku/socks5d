package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
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
	replyCommandNotSupported = uint8(7)
	replyAddressUnsupported  = uint8(8)
)

type Server struct {
	listenAddr string
	username   string
	password   string
	logger     *log.Logger
}

func NewServer(listenAddr, username, password string) *Server {
	return &Server{
		listenAddr: listenAddr,
		username:   username,
		password:   password,
		logger:     log.New(os.Stdout, "", log.LstdFlags),
	}
}

func (s *Server) ListenAndServe() error {
	listener, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return err
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			s.logger.Printf("[ERR] Accept failed: %v", err)
			continue
		}
		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	if err := s.authenticate(conn, reader); err != nil {
		s.logger.Printf("[ERR] Auth failed (%s): %v", conn.RemoteAddr(), err)
		return
	}

	if err := s.handleRequest(conn, reader); err != nil {
		s.logger.Printf("[ERR] Request failed (%s): %v", conn.RemoteAddr(), err)
	}
}

func (s *Server) authenticate(conn net.Conn, reader *bufio.Reader) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil {
		return err
	}
	if header[0] != socksVersion {
		return fmt.Errorf("unsupported SOCKS version: %d", header[0])
	}

	numMethods := int(header[1])
	methods := make([]byte, numMethods)
	if _, err := io.ReadFull(reader, methods); err != nil {
		return err
	}

	method := authNoAcceptable
	if s.username == "" && s.password == "" {
		if bytes.Contains(methods, []byte{authNoAuth}) {
			method = authNoAuth
		}
	} else {
		if bytes.Contains(methods, []byte{authUserPassword}) {
			method = authUserPassword
		}
	}

	if _, err := conn.Write([]byte{socksVersion, method}); err != nil {
		return err
	}

	if method == authNoAcceptable {
		return errors.New("no acceptable authentication methods")
	}

	if method == authUserPassword {
		return s.authWithUserPass(conn, reader)
	}

	return nil
}

func (s *Server) authWithUserPass(conn net.Conn, reader *bufio.Reader) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil {
		return err
	}
	if header[0] != authVersion {
		return fmt.Errorf("unsupported auth version: %d", header[0])
	}

	ulen := int(header[1])
	user := make([]byte, ulen)
	if _, err := io.ReadFull(reader, user); err != nil {
		return err
	}

	plenByte, err := reader.ReadByte()
	if err != nil {
		return err
	}
	plen := int(plenByte)
	pass := make([]byte, plen)
	if _, err := io.ReadFull(reader, pass); err != nil {
		return err
	}

	status := authFailure
	if string(user) == s.username && string(pass) == s.password {
		status = authSuccess
	}

	conn.Write([]byte{authVersion, status})

	if status != authSuccess {
		return errors.New("authentication failed")
	}
	return nil
}

func (s *Server) handleRequest(conn net.Conn, reader *bufio.Reader) error {
	header := make([]byte, 4)
	if _, err := io.ReadFull(reader, header); err != nil {
		return err
	}
	if header[0] != socksVersion {
		return fmt.Errorf("unsupported SOCKS version: %d", header[0])
	}

	cmd := header[1]
	addrType := header[3]

	destAddr, destPort, err := readAddress(reader, addrType)
	if err != nil {
		s.sendReply(conn, replyAddressUnsupported, nil)
		return err
	}
	dest := net.JoinHostPort(destAddr, strconv.Itoa(destPort))

	switch cmd {
	case commandConnect:
		return s.handleConnect(conn, dest)
	case commandUDPAssociate:
		return s.handleUDPAssociate(conn)
	default:
		s.sendReply(conn, replyCommandNotSupported, nil)
		return fmt.Errorf("unsupported command: %d", cmd)
	}
}

func (s *Server) handleConnect(conn net.Conn, dest string) error {
	target, err := net.Dial("tcp", dest)
	if err != nil {
		s.sendReply(conn, replyServerFailure, nil)
		return err
	}
	defer target.Close()

	if err := s.sendReply(conn, replySucceeded, target.LocalAddr()); err != nil {
		return err
	}

	errc := make(chan error, 2)
	go func() {
		_, err := io.Copy(target, conn)
		errc <- err
	}()
	go func() {
		_, err := io.Copy(conn, target)
		errc <- err
	}()

	<-errc
	return nil
}

func (s *Server) handleUDPAssociate(conn net.Conn) error {
	// Start a UDP listener on a random port
	udpAddr, err := net.ResolveUDPAddr("udp", ":0")
	if err != nil {
		s.sendReply(conn, replyServerFailure, nil)
		return err
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		s.sendReply(conn, replyServerFailure, nil)
		return err
	}
	defer udpConn.Close()

	// Reply to client with the UDP port they should send packets to
	if err := s.sendReply(conn, replySucceeded, udpConn.LocalAddr()); err != nil {
		return err
	}

	// The client's TCP connection IP. We use this to verify incoming UDP packets.
	clientTCPAddr := conn.RemoteAddr().(*net.TCPAddr)
	clientIP := clientTCPAddr.IP

	// Channel to signal TCP disconnect
	done := make(chan struct{})
	go func() {
		io.Copy(io.Discard, conn) // Block until TCP connection closes
		close(done)
		udpConn.Close()
	}()

	// Read UDP packets
	buf := make([]byte, 65535)
	for {
		n, clientUdpAddr, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-done:
				return nil
			default:
				return err
			}
		}

		// Security: Only process packets from the IP that established the TCP connection
		if !clientUdpAddr.IP.Equal(clientIP) {
			continue
		}

		go s.processUDPPacket(udpConn, clientUdpAddr, buf[:n])
	}
}

func (s *Server) processUDPPacket(udpConn *net.UDPConn, clientAddr *net.UDPAddr, packet []byte) {
	if len(packet) < 4 {
		return
	}
	if packet[0] != 0 || packet[1] != 0 {
		return // RSV must be 0
	}
	if packet[2] != 0 {
		return // Fragments not supported
	}

	addrType := packet[3]
	reader := bytes.NewReader(packet[4:])

	destAddr, destPort, err := readAddress(reader, addrType)
	if err != nil {
		return
	}
	dest := net.JoinHostPort(destAddr, strconv.Itoa(destPort))

	targetAddr, err := net.ResolveUDPAddr("udp", dest)
	if err != nil {
		return
	}

	payloadLen := reader.Len()
	payload := make([]byte, payloadLen)
	reader.Read(payload)

	// Send to target
	relayConn, err := net.DialUDP("udp", nil, targetAddr)
	if err != nil {
		return
	}
	defer relayConn.Close()

	relayConn.Write(payload)

	// Wait for response
	respBuf := make([]byte, 65535)
	n, _, err := relayConn.ReadFromUDP(respBuf)
	if err != nil {
		return
	}

	// Pack response back to SOCKS5 client
	s.sendUDPReply(udpConn, clientAddr, targetAddr, respBuf[:n])
}

func (s *Server) sendUDPReply(udpConn *net.UDPConn, clientAddr *net.UDPAddr, targetAddr *net.UDPAddr, payload []byte) {
	var buf bytes.Buffer
	buf.Write([]byte{0, 0, 0}) // RSV and FRAG

	ip := targetAddr.IP.To4()
	if ip != nil {
		buf.WriteByte(addressIPv4)
		buf.Write(ip)
	} else {
		ip = targetAddr.IP.To16()
		buf.WriteByte(addressIPv6)
		buf.Write(ip)
	}

	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, uint16(targetAddr.Port))
	buf.Write(portBuf)

	buf.Write(payload)

	udpConn.WriteToUDP(buf.Bytes(), clientAddr)
}

func readAddress(reader io.Reader, addrType byte) (string, int, error) {
	var host string
	switch addrType {
	case addressIPv4:
		ip := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(reader, ip); err != nil {
			return "", 0, err
		}
		host = net.IP(ip).String()
	case addressIPv6:
		ip := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(reader, ip); err != nil {
			return "", 0, err
		}
		host = net.IP(ip).String()
	case addressDomain:
		lenByte := make([]byte, 1)
		if _, err := io.ReadFull(reader, lenByte); err != nil {
			return "", 0, err
		}
		domain := make([]byte, lenByte[0])
		if _, err := io.ReadFull(reader, domain); err != nil {
			return "", 0, err
		}
		host = string(domain)
	default:
		return "", 0, errors.New("unsupported address type")
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(reader, portBuf); err != nil {
		return "", 0, err
	}
	port := int(binary.BigEndian.Uint16(portBuf))

	return host, port, nil
}

func (s *Server) sendReply(conn net.Conn, rep byte, localAddr net.Addr) error {
	reply := []byte{socksVersion, rep, 0, addressIPv4, 0, 0, 0, 0, 0, 0}

	if localAddr != nil {
		switch addr := localAddr.(type) {
		case *net.TCPAddr:
			ip := addr.IP.To4()
			if ip != nil {
				copy(reply[4:8], ip)
			}
			binary.BigEndian.PutUint16(reply[8:10], uint16(addr.Port))
		case *net.UDPAddr:
			ip := addr.IP.To4()
			if ip != nil {
				copy(reply[4:8], ip)
			}
			binary.BigEndian.PutUint16(reply[8:10], uint16(addr.Port))
		}
	}

	_, err := conn.Write(reply)
	return err
}