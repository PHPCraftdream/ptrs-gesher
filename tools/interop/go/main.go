// A finite obfs4 wire peer used by tools/interop/run.py.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"

	"gitlab.com/yawning/obfs4.git/transports/obfs4"
	pt "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib"
)

const (
	payloadSize = 4096
	nodeID      = "00112233445566778899aabbccddeeff00112233"
	privateKey  = "0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210"
	drbgSeed    = "0a0b0c0d0e0f0a0b0c0d0e0f0a0b0c0d0e0f0a0b0c0d0e0f"
)

func main() {
	if len(os.Args) < 2 {
		fatalf("usage: interop-go server|client|malformed-server [options]")
	}
	switch os.Args[1] {
	case "server":
		server(os.Args[2:])
	case "client":
		client(os.Args[2:])
	case "malformed-server":
		malformedServer(os.Args[2:])
	default:
		fatalf("unknown mode %q", os.Args[1])
	}
}

func server(argv []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:0", "listen address")
	stateDir := fs.String("state-dir", "", "state directory")
	iat := fs.Int("iat-mode", 0, "obfs4 IAT mode")
	_ = fs.Parse(argv)
	if *stateDir == "" {
		fatalf("server requires --state-dir")
	}
	factory := newServerFactory(*stateDir, *iat)
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		fatalf("listen: %v", err)
	}
	defer listener.Close()
	cert, ok := factory.Args().Get("cert")
	if !ok {
		fatalf("server factory did not return a cert")
	}
	fmt.Printf("READY %s %s\n", listener.Addr().String(), cert)
	conn, err := listener.Accept()
	if err != nil {
		fatalf("accept: %v", err)
	}
	defer conn.Close()
	wrapped, err := factory.WrapConn(conn)
	if err != nil {
		fatalf("obfs4 server handshake: %v", err)
	}
	if err := serveExchange(wrapped); err != nil {
		fatalf("server exchange: %v", err)
	}
	fmt.Println("OK")
}

func newServerFactory(stateDir string, iat int) interface {
	Args() *pt.Args
	WrapConn(net.Conn) (net.Conn, error)
} {
	args := &pt.Args{}
	args.Add("node-id", nodeID)
	args.Add("private-key", privateKey)
	args.Add("drbg-seed", drbgSeed)
	args.Add("iat-mode", strconv.Itoa(iat))
	factory, err := (&obfs4.Transport{}).ServerFactory(stateDir, args)
	if err != nil {
		fatalf("server factory: %v", err)
	}
	return factory
}

func client(argv []string) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	addr := fs.String("addr", "", "server address")
	cert := fs.String("cert", "", "obfs4 cert")
	iat := fs.Int("iat-mode", 0, "obfs4 IAT mode")
	_ = fs.Parse(argv)
	if *addr == "" || *cert == "" {
		fatalf("client requires --addr and --cert")
	}
	args := &pt.Args{}
	args.Add("cert", *cert)
	args.Add("iat-mode", strconv.Itoa(*iat))
	transport := &obfs4.Transport{}
	factory, err := transport.ClientFactory("")
	if err != nil {
		fatalf("client factory: %v", err)
	}
	parsed, err := factory.ParseArgs(args)
	if err != nil {
		fatalf("client args: %v", err)
	}
	conn, err := factory.Dial("tcp", *addr, net.Dial, parsed)
	if err != nil {
		fatalf("obfs4 client handshake: %v", err)
	}
	defer conn.Close()
	if err := clientExchange(conn); err != nil {
		fatalf("client exchange: %v", err)
	}
	fmt.Println("OK")
}

func malformedServer(argv []string) {
	fs := flag.NewFlagSet("malformed-server", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:0", "listen address")
	stateDir := fs.String("state-dir", "", "state directory")
	_ = fs.Parse(argv)
	if *stateDir == "" {
		fatalf("malformed-server requires --state-dir")
	}
	factory := newServerFactory(*stateDir, 0)
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		fatalf("listen: %v", err)
	}
	defer listener.Close()
	cert, ok := factory.Args().Get("cert")
	if !ok {
		fatalf("server factory did not return a cert")
	}
	fmt.Printf("READY %s %s\n", listener.Addr().String(), cert)
	conn, err := listener.Accept()
	if err != nil {
		fatalf("accept: %v", err)
	}
	defer conn.Close()
	if _, err := io.ReadFull(conn, make([]byte, 1)); err != nil {
		fatalf("did not receive client hello: %v", err)
	}
	fmt.Println("READ_HELLO")
	if _, err := conn.Write([]byte("not-an-obfs4-handshake")); err != nil {
		fatalf("malformed reply: %v", err)
	}
	fmt.Println("MALFORMED_SENT")
	fmt.Println("OK")
}

func serveExchange(conn net.Conn) error {
	want := bytes.Repeat([]byte{'C'}, payloadSize)
	got := make([]byte, payloadSize)
	if _, err := io.ReadFull(conn, got); err != nil {
		return err
	}
	if !bytes.Equal(got, want) {
		return fmt.Errorf("client payload mismatch")
	}
	if _, err := conn.Write(bytes.Repeat([]byte{'S'}, payloadSize)); err != nil {
		return err
	}
	return drain(conn)
}

func clientExchange(conn net.Conn) error {
	if _, err := conn.Write(bytes.Repeat([]byte{'C'}, payloadSize)); err != nil {
		return err
	}
	got := make([]byte, payloadSize)
	if _, err := io.ReadFull(conn, got); err != nil {
		return err
	}
	if !bytes.Equal(got, bytes.Repeat([]byte{'S'}, payloadSize)) {
		return fmt.Errorf("server reply mismatch")
	}
	return drain(conn)
}

func drain(conn net.Conn) error {
	n, err := io.Copy(io.Discard, conn)
	if err != nil {
		return err
	}
	if n != 0 {
		return fmt.Errorf("unexpected trailing payload: %d bytes", n)
	}
	return nil
}
func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "interop-go: "+format+"\n", args...)
	os.Exit(1)
}
