// Copyright 2017 Burak Sezer
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"log"

	"github.com/hashicorp/logutils"
)

const opErrAccept = "accept"

const usage = `Secure SOCKS5 proxy server

Usage:
   gsocks5 [command] -c [config-file-path]

Commands:
   -help,   -h  Print this message.
   -version -v  Print version.
   -debug   -d  Enable debug mode.
   -config  -c  Set configuration file. It is %s by default.

The Go runtime version %s
Report bugs to https://github.com/buraksezer/gsocks5/issues`

const (
	maxPasswordLength = 20
	version           = "0.1"
	defaultConfigPath = "/etc/gsocks5/gsocks5.json"
)

var (
	path             string
	showHelp         bool
	showVersion      bool
	debug            bool
	pChangedAddrPort *string
)

var errPasswordTooLong = errors.New("Passport too long")

func init() {
	rand.Seed(time.Now().UnixNano())
}

func closeConn(conn net.Conn) {
	err := conn.Close()
	if err != nil {
		if opErr, ok := err.(*net.OpError); !ok || (ok && opErr.Op != opErrAccept) {
			log.Println("[DEBUG] gsocks5: Error while closing socket", conn.RemoteAddr(), err)
		}
	}
}

func http_server(cfg config) {
	var lock sync.Mutex

	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		io.WriteString(w, "hello, world!\n")
	})

	http.HandleFunc("/port", func(w http.ResponseWriter, req *http.Request) {

		r := rand.New(rand.NewSource(time.Now().UnixNano()))
		str_arr := strings.Split(cfg.ServerAddr, ":")
		port, err := strconv.Atoi(str_arr[1])
		if err != nil {
			io.WriteString(w, cfg.ServerAddr)
			return
		}
		port += r.Intn(100)
		s := str_arr[0] + ":" + strconv.Itoa(port)
		lock.Lock()
		pChangedAddrPort = &s
		lock.Unlock()

		io.WriteString(w, *pChangedAddrPort)
		selfpid := syscall.Getpid()
		log.Printf("main: send pid: %v SIGUSER1, to restart service and change port", selfpid)
		syscall.Kill(selfpid, syscall.SIGUSR1)
	})

	if e := http.ListenAndServeTLS(":9000", "cert.pem", "unencrypted.key", nil); e != nil {
		log.Fatal("ListenAndServe: ", e)
	}
}

func main() {
	// Parse command line parameters
	f := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	f.SetOutput(ioutil.Discard)
	f.BoolVar(&showHelp, "h", false, "")
	f.BoolVar(&showHelp, "help", false, "")
	f.BoolVar(&showVersion, "version", false, "")
	f.BoolVar(&showVersion, "v", false, "")
	f.BoolVar(&debug, "d", false, "")
	f.BoolVar(&debug, "debug", false, "")
	f.StringVar(&path, "config", defaultConfigPath, "")
	f.StringVar(&path, "c", defaultConfigPath, "")

	if err := f.Parse(os.Args[1:]); err != nil {
		log.Fatalf("[ERR] Failed to parse flags: %s", err)
	}

	if showHelp {
		msg := fmt.Sprintf(usage, defaultConfigPath, runtime.Version())
		fmt.Println(msg)
		return
	} else if showVersion {
		fmt.Println("gsocks5 version", version)
		return
	}
	cfg, err := newConfig(path)
	if err != nil {
		log.Fatalf("[ERR] Failed to load configuration: %s", err)
	}

	filter := &logutils.LevelFilter{
		Levels: []logutils.LogLevel{"DEBUG", "WARN", "ERR", "INF"},
		Writer: os.Stderr,
	}
	if debug || cfg.Debug {
		filter.MinLevel = logutils.LogLevel("DEBUG")
	} else {
		filter.MinLevel = logutils.LogLevel("WARN")
	}
	log.SetOutput(filter)

	// Handle SIGINT and SIGTERM.
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGUSR1)

	pChangedAddrPort = &cfg.ServerAddr

	go http_server(cfg)

	for true {
		switch {
		case cfg.Role == roleClient:
			log.Print("[INF] gsocks5: Running as client")
			cl := newClient(cfg, sigChan)
			if err = cl.run(); err != nil {
				log.Fatalf("[ERR] gsocks5: failed to serve %s", err)
			}
		case cfg.Role == roleServer:
			log.Print("[INF] gsocks5: Running as server")
			srv := newServer(cfg, sigChan)
			if err = srv.run(&pChangedAddrPort); err != nil {
				log.Fatalf("[ERR] gsocks5: failed to serve %s", err)
			}
		}
		log.Print("[INF] Goodbye!")
	}
}
