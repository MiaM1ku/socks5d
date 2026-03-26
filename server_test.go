package main

import (
	"bufio"
	"io"
	"net"
	"testing"
	"time"
)

func TestConnectNoAuth(t *testing.T) {
	backend, closeBackend := startTCPEcho(t)
	defer closeBackend()

	serverAddr, closeServer := startServer(t, "", "")
	defer closeServer()

	conn := dialSOCKS(t, serverAddr, "", "")
	defer conn.Close()

	if err := sendConnectRequest(conn, backend); err != nil {
		t.Fatalf("connect request failed: %v", err)
	}

	message := []byte("hello over tcp")
	if _, err := conn.Write(message); err != nil {
		t.Fatalf("write through proxy failed: %v", err)
	}

	buf := make([]byte, len(message))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read through proxy failed: %v", err)
	}
	if string(buf) != string(message) {
		t.Fatalf("unexpected tcp echo: got %q want %q", string(buf), string(message))
	}
}

func TestConnectWithAuth(t *testing.T) {
	backend, closeBackend := startTCPEcho(t)
	defer closeBackend()

	serverAddr, closeServer := startServer(t, "user", "pass")
	defer closeServer()

	conn := dialSOCKS(t, serverAddr, "user", "pass")
	defer conn.Close()

	if err := sendConnectRequest(conn, backend); err != nil {
		t.Fatalf("connect request failed: %v", err)
	}
}

func TestUDPAssociate(t *testing.T) {
	backend, closeBackend := startUDPEcho(t)
	defer closeBackend()

	serverAddr, closeServer := startServer(t, "", "")
	defer closeServer()

	controlConn := dialSOCKS(t, serverAddr, "", "")
	defer controlConn.Close()

	udpRelay := sendUDPAssociateRequest(t, controlConn)

	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("listen UDP client failed: %v", err)
	}
	defer clientConn.Close()

	if err := clientConn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set UDP deadline failed: %v", err)
	}

	packet, err := buildUDPPacket(NewAddrSpecFromUDP(backend), []byte("hello over udp"))
	if err != nil {
		t.Fatalf("build UDP packet failed: %v", err)
	}
	if _, err := clientConn.WriteToUDP(packet, udpRelay); err != nil {
		t.Fatalf("send UDP packet failed: %v", err)
	}

	buf := make([]byte, 64*1024)
	n, _, err := clientConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read UDP reply failed: %v", err)
	}

	source, payload, err := parseUDPPacket(buf[:n])
	if err != nil {
		t.Fatalf("parse UDP reply failed: %v", err)
	}
	if !source.ip.Equal(backend.IP) || source.port != backend.Port {
		t.Fatalf("unexpected UDP source: got %s want %s", source.address(), backend.String())
	}
	if string(payload) != "hello over udp" {
		t.Fatalf("unexpected UDP payload: got %q", string(payload))
	}
}

func startServer(t *testing.T, username, password string) (string, func()) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen server failed: %v", err)
	}

	server := NewServer(listener.Addr().String(), username, password)
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(listener)
	}()

	return listener.Addr().String(), func() {
		_ = listener.Close()
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatalf("server exited with error: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for server shutdown")
		}
	}
}

func startTCPEcho(t *testing.T) (string, func()) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen TCP echo failed: %v", err)
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	return listener.Addr().String(), func() { _ = listener.Close() }
}

func startUDPEcho(t *testing.T) (*net.UDPAddr, func()) {
	t.Helper()

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen UDP echo failed: %v", err)
	}

	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, peer, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = conn.WriteToUDP(buf[:n], peer)
		}
	}()

	return conn.LocalAddr().(*net.UDPAddr), func() { _ = conn.Close() }
}

func dialSOCKS(t *testing.T, serverAddr, username, password string) net.Conn {
	t.Helper()

	conn, err := net.DialTimeout("tcp", serverAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial SOCKS server failed: %v", err)
	}
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set conn deadline failed: %v", err)
	}

	if username == "" {
		if _, err := conn.Write([]byte{socksVersion, 1, authNoAuth}); err != nil {
			t.Fatalf("write auth methods failed: %v", err)
		}
		reply := make([]byte, 2)
		if _, err := io.ReadFull(conn, reply); err != nil {
			t.Fatalf("read auth reply failed: %v", err)
		}
		if reply[1] != authNoAuth {
			t.Fatalf("unexpected auth method: %d", reply[1])
		}
		return conn
	}

	if _, err := conn.Write([]byte{socksVersion, 1, authUserPassword}); err != nil {
		t.Fatalf("write auth methods failed: %v", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read auth method reply failed: %v", err)
	}
	if reply[1] != authUserPassword {
		t.Fatalf("unexpected auth method: %d", reply[1])
	}

	authReq := append([]byte{authVersion, byte(len(username))}, []byte(username)...)
	authReq = append(authReq, byte(len(password)))
	authReq = append(authReq, []byte(password)...)
	if _, err := conn.Write(authReq); err != nil {
		t.Fatalf("write auth request failed: %v", err)
	}
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read auth status failed: %v", err)
	}
	if reply[1] != authSuccess {
		t.Fatalf("unexpected auth status: %d", reply[1])
	}
	return conn
}

func sendConnectRequest(conn net.Conn, targetAddr string) error {
	reader := bufio.NewReader(conn)
	host, portText, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return err
	}
	port, err := net.LookupPort("tcp", portText)
	if err != nil {
		return err
	}

	ip := net.ParseIP(host)
	dest := addrSpec{host: host, port: port}
	if ip != nil {
		dest.ip = ip
		dest.host = ""
	}

	req := []byte{socksVersion, commandConnect, 0}
	packet, err := buildUDPPacket(dest, nil)
	if err != nil {
		return err
	}
	req = append(req, packet[3:]...)
	if _, err := conn.Write(req); err != nil {
		return err
	}

	header := make([]byte, 3)
	if _, err := io.ReadFull(reader, header); err != nil {
		return err
	}
	if header[1] != replySucceeded {
		return io.ErrUnexpectedEOF
	}
	replyAddr, err := readAddrSpec(reader)
	if err != nil {
		return err
	}
	_ = replyAddr
	return nil
}

func sendUDPAssociateRequest(t *testing.T, conn net.Conn) *net.UDPAddr {
	t.Helper()

	req := []byte{socksVersion, commandUDPAssociate, 0, addressIPv4, 0, 0, 0, 0, 0, 0}
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write UDP associate request failed: %v", err)
	}

	reader := bufio.NewReader(conn)
	header := make([]byte, 3)
	if _, err := io.ReadFull(reader, header); err != nil {
		t.Fatalf("read UDP associate reply failed: %v", err)
	}
	if header[1] != replySucceeded {
		t.Fatalf("unexpected UDP associate reply: %d", header[1])
	}
	addr, err := readAddrSpec(reader)
	if err != nil {
		t.Fatalf("read UDP relay address failed: %v", err)
	}
	return &net.UDPAddr{IP: addr.ip, Port: addr.port}
}
