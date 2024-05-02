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
	"github.com/poolpOrg/OpenSMTPD-framework/filter"
)

type session struct {
	id string
	tm int64

	ip       net.IP
	heloName string
	userName string

	mailFrom   string
	fromDomain string
	rcptTo     string

	ok           bool
	local_sender bool
}

var sessions = make(map[string]*session)

var whitelist_src = make(map[string]int64)
var whitelist_domain = make(map[string]int64)
var whitelist_domain_static = []string{}
var wl_src_mux sync.Mutex
var wl_dom_mux sync.Mutex

var greylist_src = make(map[string]int64)
var greylist_domain = make(map[string]int64)
var gl_src_mux sync.Mutex
var gl_dom_mux sync.Mutex

var passtime *int64
var greyexp *int64
var whiteexp *int64
var ip_wl *string
var domain_wl *string

func linkConnectCb(timestamp time.Time, sessionId string, rdns string, fcrdns string, src net.Addr, dest net.Addr) {
	s := &session{}
	s.id = sessionId
	sessions[s.id] = s

	if addr, ok := src.(*net.TCPAddr); !ok {
		fmt.Fprintf(os.Stderr, "connection from local socket, session whitelisted\n")
		s.ok = true
		s.local_sender = true
	} else {
		s.ip = addr.IP
		fmt.Fprintf(os.Stderr, "connection received from src %s\n", s.ip.String())
	}
}

func linkDisconnectCb(timestamp time.Time, sessionId string) {
	delete(sessions, sessionId)
}

func linkIdentifyCb(timestamp time.Time, sessionId string, method string, identity string) {
	s := sessions[sessionId]
	s.heloName = identity
}

func linkAuthCb(timestamp time.Time, sessionId string, result string, username string) {
	if result != "pass" {
		return
	}

	s := sessions[sessionId]
	s.userName = username

	// no greylisting for authenticated sessions
	s.ok = true
	s.local_sender = true
}

func txMailCb(timestamp time.Time, sessionId string, messageId string, result string, from string) {
	if result != "ok" {
		return
	}

	var domain string
	s := sessions[sessionId]
	s.mailFrom = from
	tmp := strings.Split(s.mailFrom, "@")
	if len(tmp) == 1 {
		domain = s.heloName
	} else {
		domain = tmp[1]
	}
	s.fromDomain = domain
}

func txRcptCb(timestamp time.Time, sessionId string, messageId string, result string, to string) {
	if result != "ok" {
		return
	}

	s := sessions[sessionId]
	if !s.local_sender {
		return
	}

	tmp := strings.Split(to, "@")
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

func rcptTo(timestamp time.Time, sessionId string, to string) filter.Response {
	s := sessions[sessionId]
	s.rcptTo = to
	if s.ok {
		fmt.Fprintf(os.Stderr, "session is whitelisted\n")
		return filter.Proceed()
	}

	wl_src_mux.Lock()
	defer wl_src_mux.Unlock()

	key := fmt.Sprintf("ip=%s", s.ip.String())
	if val, ok := whitelist_src[key]; ok {
		if s.tm-val < *whiteexp {
			fmt.Fprintf(os.Stderr, "IP address %s is whitelisted\n", s.ip.String())
			whitelist_src[key] = s.tm
			return filter.Proceed()
		}
	}

	wl_dom_mux.Lock()
	defer wl_dom_mux.Unlock()

	key = fmt.Sprintf("domain=%s", s.fromDomain)
	// if domain is in whitelist file from cmdline then proceed
	for _, item := range whitelist_domain_static {
		if item == key {
			fmt.Fprintf(os.Stderr, "domain %s is whitelisted in %s\n", s.fromDomain, *domain_wl)
			return filter.Proceed()
		}
	}
	if val, ok := whitelist_domain[key]; ok {
		if s.tm-val < *whiteexp {
			res, _ := spf.CheckHostWithSender(s.ip, s.heloName, s.mailFrom)
			if res == "pass" {
				fmt.Fprintf(os.Stderr, "domain %s is whitelisted\n", s.fromDomain)
				whitelist_domain[key] = s.tm
				return filter.Proceed()
			}
		}
	}

	return spfResolve(s)
}

func spfResolve(s *session) filter.Response {

	spfAware := false
	res, _ := spf.CheckHostWithSender(s.ip, s.heloName, s.mailFrom)
	if res == "pass" {
		spfAware = true
	}

	if !spfAware {
		key := fmt.Sprintf("ip=%s:%s:%s", s.ip.String(), s.mailFrom, s.rcptTo)
		gl_src_mux.Lock()
		defer gl_src_mux.Unlock()
		if val, ok := greylist_src[key]; ok {
			delta := s.tm - val
			if val != s.tm && delta < *greyexp && delta > *passtime {
				fmt.Fprintf(os.Stderr, "IP %s added to whitelist\n", s.ip.String())
				key = fmt.Sprintf("ip=%s", s.ip.String())

				wl_src_mux.Lock()
				defer wl_src_mux.Unlock()

				whitelist_src[key] = s.tm
				s.ok = true
				return filter.Proceed()

			}
		} else {
			fmt.Fprintf(os.Stderr, "IP %s added to greylist\n", s.ip.String())
		}
		greylist_src[key] = s.tm
		return filter.Reject("451 greylisted, try again later")
	}

	gl_dom_mux.Lock()
	defer gl_dom_mux.Unlock()
	key := fmt.Sprintf("domain=%s:%s:%s", s.fromDomain, s.mailFrom, s.rcptTo)
	if val, ok := greylist_domain[key]; ok {
		delta := s.tm - val
		if val != s.tm && delta < *greyexp && delta > *passtime {
			fmt.Fprintf(os.Stderr, "domain %s added to whitelist\n", s.fromDomain)
			key = fmt.Sprintf("domain=%s", s.fromDomain)

			wl_dom_mux.Lock()
			defer wl_dom_mux.Unlock()

			whitelist_domain[key] = s.tm
			s.ok = true
			return filter.Proceed()
		}
	} else {
		fmt.Fprintf(os.Stderr, "domain %s added to greylist\n", s.fromDomain)
	}
	greylist_domain[key] = s.tm
	return filter.Reject("451 greylisted, try again later")
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
			whitelist_domain_static = append(whitelist_domain_static, key)
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
		case <-tick:
			now := int64(time.Now().Unix())

			gl_src_mux.Lock()
			for key, value := range greylist_src {
				if now-value > *greyexp {
					delete(greylist_src, key)
				}
			}
			gl_src_mux.Unlock()

			gl_dom_mux.Lock()
			for key, value := range greylist_domain {
				if now-value > *greyexp {
					delete(greylist_domain, key)
				}
			}
			gl_dom_mux.Unlock()

			wl_src_mux.Lock()
			for key, value := range whitelist_src {
				if now-value > *whiteexp {
					delete(whitelist_src, key)
				}
			}
			wl_src_mux.Unlock()

			wl_dom_mux.Lock()
			for key, value := range whitelist_domain {
				if now-value > *whiteexp {
					delete(whitelist_domain, key)
				}
			}
			wl_dom_mux.Unlock()
		}
	}
}

func main() {
	passtime = flag.Int64("passtime", 300, "number of seconds before retries are accounted (default: 300)")
	greyexp = flag.Int64("greyexp", 4*3600, "number of seconds before greylist attempts expire (default: 4 hours)")
	whiteexp = flag.Int64("whiteexp", 30*86400, "number of seconds before whitelists expire (default: 30 days)")
	ip_wl = flag.String("wl-ip", "", "filename containing a list of IP addresses to whitelist, one per line")
	domain_wl = flag.String("wl-domain", "", "filename containing a list of sender domains to whitelist, one per line")

	flag.Parse()

	loadWhitelists()
	go listsManager()

	filter.Init()

	filter.SMTP_IN.OnLinkConnect(linkConnectCb)
	filter.SMTP_IN.OnLinkDisconnect(linkDisconnectCb)
	filter.SMTP_IN.OnLinkIdentify(linkIdentifyCb)
	filter.SMTP_IN.OnLinkAuth(linkAuthCb)
	filter.SMTP_IN.OnTxMail(txMailCb)
	filter.SMTP_IN.OnTxRcpt(txRcptCb)

	filter.SMTP_IN.RcptToRequest(rcptTo)

	filter.Dispatch()
}
