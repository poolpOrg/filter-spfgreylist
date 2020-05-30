//
// Copyright (c) 2019 Gilles Chehade <gilles@poolp.org>
//
// Permission to use, copy, modify, and distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
//

package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"log"

	"blitiri.com.ar/go/spf"
)

type session struct {
	id       string
	tm	 int64

	ip	 net.IP
	heloName string
	userName string

	mailFrom string
	fromDomain string
	rcptTo	 string

	ok	 bool
	local_sender	 bool
}
var sessions = make(map[string]*session)

var whitelist_src = make(map[string]int64)
var whitelist_domain = make(map[string]int64)
var wl_src_mux sync.Mutex
var wl_dom_mux sync.Mutex

var greylist_src = make(map[string]int64)
var greylist_domain = make(map[string]int64)
var gl_src_mux sync.Mutex
var gl_dom_mux sync.Mutex


var passtime	*int64
var greyexp	*int64
var whiteexp	*int64
var ip_wl	*string
var domain_wl	*string

var version	string

var outputChannel chan string

var reporters = map[string]func(*session, []string){
	"link-connect":    linkConnect,
	"link-disconnect": linkDisconnect,
	"link-identify":   linkIdentify,
	"link-auth":       linkAuth,
	"tx-mail":	   txMail,
	"tx-rcpt":	   txRcpt,
}

var filters = map[string]func(*session, []string){
	"rcpt-to":	rcptTo,
}

func produceOutput(msgType string, sessionId string, token string, format string, a ...interface{}) {
	var out string

	if version < "0.5" {
		out = msgType + "|" + token + "|" + sessionId
	} else {
		out = msgType + "|" + sessionId + "|" + token
	}
	out += "|" + fmt.Sprintf(format, a...)

	outputChannel <- out
}

func proceed(sessid string, token string) {
	produceOutput("filter-result", sessid, token, "proceed")
}

func reject(sessid string, token string) {
	produceOutput("filter-result", sessid, token, "reject|451 greylisted, try again later")
}

func linkConnect(s *session, params []string) {
	if len(params) != 4 {
		log.Fatal("invalid input, shouldn't happen")
	}

	s.tm = int64(time.Now().Unix())
	src := params[2]
	tmp := strings.Split(src, ":")
	tmp = tmp[0:len(tmp)-1]
	src = strings.Join(tmp, ":")
	if strings.HasPrefix(src, "[") {
		src = src[1:len(src)-1]
	}

	s.ip = net.ParseIP(src)
	if s.ip == nil {
		fmt.Fprintf(os.Stderr, "connection from local socket, session whitelisted\n")
		s.ok = true
		s.local_sender = true
		return
	}

	fmt.Fprintf(os.Stderr, "connection received from src %s\n", s.ip.String())
}

func linkDisconnect(s *session, params []string) {
	if len(params) != 0 {
		log.Fatal("invalid input, shouldn't happen")
	}
	delete(sessions, s.id)
}

func linkIdentify(s *session, params []string) {
	if len(params) != 2 {
		log.Fatal("invalid input, shouldn't happen: %r", params)
	}
	s.heloName = params[1]
}

func linkAuth(s *session, params []string) {
	if len(params) != 2 {
		log.Fatal("invalid input, shouldn't happen")
	}
	if params[1] != "pass" {
		return
	}

	s.userName = params[0]

	// no greylisting for authenticated sessions
	s.ok = true
	s.local_sender = true
}

func txMail(s *session, params []string) {
	if len(params) < 3 {
		log.Fatal("invalid input, shouldn't happen")
	}

	var status string
	var mailaddr string

	if version < "0.6" {
		_ = params[0]
		mailaddr = strings.Join(params[1:len(params)-1], "|")
		status = params[len(params)-1]
	} else {
		_ = params[0]
		status = params[1]
		mailaddr = strings.Join(params[2:], "|")
	}

	if status != "ok" {
		return
	}

	s.mailFrom = mailaddr
	domain := s.mailFrom
	tmp := strings.Split(s.mailFrom, "@")
	if len(tmp) == 1 {
		domain = s.heloName
	} else {
		domain = tmp[1]
	}
	s.fromDomain = domain
}

func txRcpt(s *session, params []string) {
	if len(params) < 3 {
		log.Fatal("invalid input, shouldn't happen")
	}

	var status string
	var mailaddr string

	if version < "0.6" {
		_ = params[0]
		mailaddr = strings.Join(params[1:len(params)-1], "|")
		status = params[len(params)-1]
	} else {
		fmt.Fprintf(os.Stderr, "txMail: new Format\n")
		_ = params[0]
		status = params[1]
		mailaddr = strings.Join(params[2:], "|")
	}

	if ! s.local_sender {
		return
	}

	if status != "ok" {
		return
	}

	tmp := strings.Split(mailaddr, "@")
	if len(tmp) == 1 {
		return
	}
	domain := tmp[1]

	key := fmt.Sprintf("domain=%s", domain)
	fmt.Fprintf(os.Stderr, "domain %s is whitelisted\n", domain)
	wl_dom_mux.Lock()
	whitelist_domain[key] = s.tm
	wl_dom_mux.Unlock()
}

func rcptTo(s *session, params []string) {
	if len(params) < 2 {
		log.Fatal("invalid input, shouldn't happen")
	}

	token := params[0]
	s.rcptTo = strings.Join(params[1:], "|")

	if s.ok {
		fmt.Fprintf(os.Stderr, "session is whitelisted\n")
		proceed(s.id, token)
		return
	}

	wl_src_mux.Lock()
	defer wl_src_mux.Unlock()

	key := fmt.Sprintf("ip=%s", s.ip.String())
	if val, ok := whitelist_src[key]; ok {
		if s.tm - val < *whiteexp {
			fmt.Fprintf(os.Stderr, "IP address %s is whitelisted\n", s.ip.String())
			proceed(s.id, token)
			whitelist_src[key] = s.tm
			return
		}
	}

	wl_dom_mux.Lock()
	defer wl_dom_mux.Unlock()

	key = fmt.Sprintf("domain=%s", s.fromDomain)
	if val, ok := whitelist_domain[key]; ok {
		if s.tm - val < *whiteexp {
			res, _ := spf.CheckHostWithSender(s.ip, s.heloName, s.mailFrom)
			if (res == "pass") {
				fmt.Fprintf(os.Stderr, "domain %s is whitelisted\n", s.fromDomain)
				proceed(s.id, token)
				whitelist_domain[key] = s.tm
				return
			}
		}
	}

	go spfResolve(s, token)
	return
}

func spfResolve(s *session, token string) {

	spfAware := false
	res, _ := spf.CheckHostWithSender(s.ip, s.heloName, s.mailFrom)
	if (res == "pass") {
		spfAware = true
	}

	if (!spfAware) {
		key := fmt.Sprintf("ip=%s:%s:%s", s.ip.String(), s.mailFrom, s.rcptTo)
		gl_src_mux.Lock()
		defer gl_src_mux.Unlock()
		if val, ok := greylist_src[key]; ok {
			delta := s.tm - val
			if val != s.tm && delta < *greyexp && delta > *passtime {
				fmt.Fprintf(os.Stderr, "IP %s added to whitelist\n", s.ip.String())
				proceed(s.id, token)
				key = fmt.Sprintf("ip=%s", s.ip.String())

				wl_src_mux.Lock()
				defer wl_src_mux.Unlock()

				whitelist_src[key] = s.tm
				s.ok = true
				return
			}
		} else {
			fmt.Fprintf(os.Stderr, "IP %s added to greylist\n", s.ip.String())
		}
		greylist_src[key] = s.tm
		reject(s.id, token)
		return
	}		

	gl_dom_mux.Lock()
	defer gl_dom_mux.Unlock()
	key := fmt.Sprintf("domain=%s:%s:%s", s.fromDomain, s.mailFrom, s.rcptTo)
	if val, ok := greylist_domain[key]; ok {
		delta := s.tm - val
		if val != s.tm && delta < *greyexp && delta > *passtime {
			fmt.Fprintf(os.Stderr, "domain %s added to whitelist\n", s.fromDomain)
			proceed(s.id, token)
			key = fmt.Sprintf("domain=%s", s.fromDomain)

			wl_dom_mux.Lock()
			defer wl_dom_mux.Unlock()

			whitelist_domain[key] = s.tm
			s.ok = true
			return
		}
	} else {
		fmt.Fprintf(os.Stderr, "domain %s added to greylist\n", s.fromDomain)
	}
	greylist_domain[key] = s.tm
	reject(s.id, token)
	return
}

func filterInit() {
	for k := range reporters {
		fmt.Printf("register|report|smtp-in|%s\n", k)
	}
	for k := range filters {
		fmt.Printf("register|filter|smtp-in|%s\n", k)
	}
	fmt.Println("register|ready")
}

func trigger(actions map[string]func(*session, []string), atoms []string) {
	if atoms[4] == "link-connect" {
		// special case to simplify subsequent code
		s := session{}
		s.id = atoms[5]
		sessions[s.id] = &s
	}

	s := sessions[atoms[5]]
	if v, ok := actions[atoms[4]]; ok {
		v(s, atoms[6:])
	} else {
		os.Exit(1)
	}
}

func skipConfig(scanner *bufio.Scanner) {
	for {
		if !scanner.Scan() {
			os.Exit(0)
		}
		line := scanner.Text()
		if line == "config|ready" {
			return
		}
	}
}

func loadWhitelists() {
	now := int64(time.Now().Unix())

	if *ip_wl != "" {
		file, err := os.Open(*ip_wl)
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			fmt.Fprintf(os.Stderr, "IP %s added to whitelist\n", scanner.Text())
			key := fmt.Sprintf("ip=%s", scanner.Text())
			whitelist_src[key] = now
		}
		if err := scanner.Err(); err != nil {
			log.Fatal(err)
		}
	}

	if *domain_wl != "" {
		file, err := os.Open(*domain_wl)
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			fmt.Fprintf(os.Stderr, "domain %s added to whitelist\n", scanner.Text())
			key := fmt.Sprintf("domain=%s", scanner.Text())
			whitelist_domain[key] = now
		}
	
		if err := scanner.Err(); err != nil {
			log.Fatal(err)
		}
	}
}

func listsManager() {
	tick := time.Tick(60 * 1000 * time.Millisecond)
	for {
		select {
		case <- tick:
			now := int64(time.Now().Unix())

			gl_src_mux.Lock()
			for key, value := range greylist_src {
				if now - value > *greyexp {
					delete(greylist_src, key)
				}
			}
			gl_src_mux.Unlock()

			gl_dom_mux.Lock()
			for key, value := range greylist_domain {
				if now - value > *greyexp {
					delete(greylist_domain, key)
				}
			}
			gl_dom_mux.Unlock()
			
			wl_src_mux.Lock()
			for key, value := range whitelist_src {
				if now - value > *whiteexp {
					delete(whitelist_src, key)
				}
			}
			wl_src_mux.Unlock()

			wl_dom_mux.Lock()
			for key, value := range whitelist_domain {
				if now - value > *whiteexp {
					delete(whitelist_domain, key)
				}
			}
			wl_dom_mux.Unlock()
		}
	}
}

func main() {
	passtime  = flag.Int64("passtime", 300, "number of seconds before retries are accounted (default: 300)")
	greyexp   = flag.Int64("greyexp", 4*3600, "number of seconds before greylist attempts expire (default: 4 hours)")
	whiteexp  = flag.Int64("whiteexp", 30*86400, "number of seconds before whitelists expire (default: 30 days)")
	ip_wl     = flag.String("wl-ip", "", "filename containing a list of IP addresses to whitelist, one per line")
	domain_wl = flag.String("wl-domain", "", "filename containing a list of sender domains to whitelist, one per line")

	flag.Parse()

	loadWhitelists()
	go listsManager()

	scanner := bufio.NewScanner(os.Stdin)

	skipConfig(scanner)

	filterInit()

	outputChannel = make(chan string)
	go func() {
		for line := range outputChannel {
			fmt.Println(line)
		}
	}()

	for {
		if !scanner.Scan() {
			os.Exit(0)
		}

		atoms := strings.Split(scanner.Text(), "|")
		if len(atoms) < 6 {
			os.Exit(1)
		}

		version = atoms[1]

		switch atoms[0] {
		case "report":
			trigger(reporters, atoms)
		case "filter":
			trigger(filters, atoms)
		default:
			os.Exit(1)
		}
	}
}
