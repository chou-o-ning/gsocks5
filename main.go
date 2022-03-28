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
	"crypto/tls"
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
	"github.com/robfig/cron/v3"
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
	cn               *cron.Cron = nil
	pCfg             *config
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

	server := &http.Server{
		Addr:         ":" + cfg.HttpPort,
		ReadTimeout:  5 * time.Minute, // 5 min to allow for delays when 'curl' on OSx prompts for username/password
		WriteTimeout: 10 * time.Second,
	}

	http.HandleFunc("/port", func(w http.ResponseWriter, req *http.Request) {

		r := rand.New(rand.NewSource(time.Now().UnixNano()))
		str_arr := strings.Split(*pChangedAddrPort, ":")
		port, err := strconv.Atoi(str_arr[1])
		if err != nil {
			io.WriteString(w, *pChangedAddrPort)
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

	if e := server.ListenAndServeTLS(cfg.ServerCert, cfg.ServerKey); e != nil {
		log.Fatal("ListenAndServe: ", e)
	}
}

func getAddrPort() {
	c := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}}

	if resp, e := c.Get("https://" + pCfg.ServerAddr + ":" + pCfg.HttpPort + "/port"); e != nil {
		log.Fatal("http.Client.Get: ", e)
	} else {
		defer resp.Body.Close()
		resp.Close = true
		b, err := io.ReadAll(resp.Body)
		if err == nil {
			s := string(b)
			pChangedAddrPort = &s
		}
	}
}

func getAddrPortAndKill() {
	c := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}}

	if resp, e := c.Get("https://" + pCfg.ServerAddr + ":" + pCfg.HttpPort + "/port"); e != nil {
		log.Fatal("http.Client.Get: ", e)
	} else {
		defer resp.Body.Close()
		resp.Close = true
		b, err := io.ReadAll(resp.Body)
		if err == nil {
			s := string(b)
			pChangedAddrPort = &s
			selfpid := syscall.Getpid()
			log.Printf("main: send pid: %v SIGUSER1, to restart service and change port", selfpid)
			syscall.Kill(selfpid, syscall.SIGUSR1)
		}
	}
}

func http_client() {
	if cn != nil {
		cn.Stop()
		cn = nil
	}

	cn = cron.New(cron.WithSeconds()) //accurate to the second

	// timer
	spec := "0 0 */" + pCfg.AccessCycle + " * * ?" //Cron Expressions
	log.Print("cron expression: " + spec)
	cn.AddFunc(spec, getAddrPortAndKill)
	cn.Start()
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
	pCfg = &cfg
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

	if cfg.Role == roleClient {
		getAddrPort()
		go http_client()
	}

	if cfg.Role == roleServer {
		// 服务器初始化端口在 http 端口相距1000 + 随机值，避免端口冲突
		initPort, err := strconv.Atoi(cfg.HttpPort)
		if err != nil {
			log.Fatalf("[ERR] gsocks5: convert from string to int error: %s", err)
			return
		}
		r := rand.New(rand.NewSource(time.Now().UnixNano()))
		initPort += r.Intn(100)
		initPort += 1000
		addressPort := cfg.ServerAddr + ":" + strconv.Itoa(initPort)
		pChangedAddrPort = &addressPort

		go http_server(cfg)
	}

	for true {
		switch {
		case cfg.Role == roleClient:
			log.Print("[INF] gsocks5: Running as client")
			cl := newClient(cfg, sigChan)
			if err = cl.run(&pChangedAddrPort); err != nil {
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
