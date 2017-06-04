package main

import (
	"crypto/tls"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"
)

type client struct {
	socksAddr       string
	cfg             config
	keepAlivePeriod time.Duration
	dialTimeout     time.Duration
	wg              sync.WaitGroup
	errChan         chan error
	signal          chan os.Signal
	done            chan struct{}
}

func newClient(cfg config, sigChan chan os.Signal) *client {
	return &client{
		cfg:             cfg,
		keepAlivePeriod: time.Duration(cfg.KeepAlivePeriod) * time.Second,
		dialTimeout:     time.Duration(cfg.DialTimeout) * time.Second,
		errChan:         make(chan error, 1),
		signal:          sigChan,
		done:            make(chan struct{}),
	}
}

func (c *client) proxyClientConn(conn, rConn net.Conn, ch chan struct{}) {
	defer c.wg.Done()
	defer close(ch)
	var wg sync.WaitGroup
	connCopy := func(dst, src net.Conn) {
		defer wg.Done()
		_, err := io.Copy(dst, src)
		if err != nil {
			if opErr, ok := err.(*net.OpError); !ok || (ok && opErr.Op != "readfrom") {
				log.Println("[ERR] gsocks5: Failed to copy connection from",
					src.RemoteAddr(), "to", conn.RemoteAddr(), ":", err)
			}
			return
		}
	}

	wg.Add(2)
	go connCopy(rConn, conn)
	go connCopy(conn, rConn)
	wg.Wait()
}

func (c *client) clientConn(conn net.Conn) {
	defer c.wg.Done()
	defer closeConn(conn)

	rConn, err := net.DialTimeout(c.cfg.Method, c.socksAddr, c.dialTimeout)
	if err != nil {
		log.Println("[ERR] gsocks5: Failed to dial", c.socksAddr, err)
		return
	}
	defer closeConn(rConn)

	cfg := &tls.Config{
		InsecureSkipVerify: c.cfg.InsecureSkipVerify,
	}
	tlsConn := tls.Client(rConn, cfg)
	if err = tlsConn.Handshake(); err != nil {
		log.Println("[ERR] gsocks5: Failed to dial", c.socksAddr, err)
		return
	}

	ch := make(chan struct{})
	c.wg.Add(1)
	go c.proxyClientConn(conn, tlsConn, ch)

	select {
	case <-c.done:
	case <-ch:
	}
}

func (c *client) serve(l net.Listener) {
	defer c.wg.Done()
	for {
		conn, err := l.Accept()
		if err != nil {
			// Shutdown the client immediately.
			c.shutdown()
			if opErr, ok := err.(*net.OpError); !ok || (ok && opErr.Op != "accept") {
				c.errChan <- err
				return
			}
			c.errChan <- nil
			return
		}

		// ASSOCIATE command has not been implemented by go-socks5. We currently support TCP but when someone
		// implements ASSOCIATE command, we will implement an UDP relay in gsocks5.
		if c.cfg.Method == "tcp" {
			conn.(*net.TCPConn).SetKeepAlive(true)
			conn.(*net.TCPConn).SetKeepAlivePeriod(c.keepAlivePeriod)
		}

		c.wg.Add(1)
		go c.clientConn(conn)
	}
}

func (c *client) shutdown() {
	select {
	case <-c.done:
		return
	default:
	}
	close(c.done)
}

func (c *client) run() error {
	var err error
	host, port := c.cfg.ClientHost, c.cfg.ClientPort

	addr := net.JoinHostPort(host, port)
	c.socksAddr = net.JoinHostPort(c.cfg.ServerHost, c.cfg.ServerTLSPort)

	rawListener, err := net.Listen(c.cfg.Method, addr)
	if err != nil {
		return err
	}

	log.Println("[INF] gsocks5: Proxy client runs on", addr)
	c.wg.Add(1)
	go c.serve(rawListener)

	select {
	// Wait for SIGINT or SIGTERM
	case <-c.signal:
	// Wait for a listener error
	case <-c.done:
	}

	// Signal all running goroutines to stop.
	c.shutdown()

	log.Println("[INF] gsocks5: Stopping proxy", addr)
	if err = rawListener.Close(); err != nil {
		log.Println("[ERR] gsocks5: Failed to close listener", err)
	}

	ch := make(chan struct{})
	go func() {
		defer close(ch)
		c.wg.Wait()
	}()

	select {
	case <-ch:
	case <-time.After(time.Duration(c.cfg.GracefulPeriod) * time.Second):
		log.Println("[WARN] Some goroutines will be stopped immediately")
	}

	err = <-c.errChan
	return err
}