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
}
var sessions = make(map[string]*session)

var whitelist_src = make(map[string]int64)
var whitelist_domain = make(map[string]int64)

var greylist_src = make(map[string]int64)
var greylist_domain = make(map[string]int64)

var passtime	*int64
var greyexp	*int64
var whiteexp	*int64
var ip_wl	*string
var domain_wl	*string

var reporters = map[string]func(*session, []string){
	"link-connect":    linkConnect,
	"link-disconnect": linkDisconnect,
	"link-identify":   linkIdentify,
	"link-auth":       linkAuth,
	"tx-mail":	   txMail,
}

var filters = map[string]func(*session, []string){
	"rcpt-to":	rcptTo,
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
	if tmp[0] == "[" {
		src = src[1:len(src)-1]
	}

	//
	src = "45.76.46.201"
	//
	
	s.ip = net.ParseIP(src)
	if s.ip == nil {
		fmt.Fprintf(os.Stderr, "connection from local socket, session whitelisted\n")
		s.ok = true
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
}

func txMail(s *session, params []string) {
	if len(params) != 3 {
		log.Fatal("invalid input, shouldn't happen")
	}

	if params[2] != "ok" {
		return
	}

	s.mailFrom = params[1]
	domain := s.mailFrom
	tmp := strings.Split(s.mailFrom, "@")
	if len(tmp) == 1 {
		domain = s.heloName
	} else {
		domain = tmp[1]
	}
	s.fromDomain = domain
}

func rcptTo(s *session, params []string) {
	if len(params) != 2 {
		log.Fatal("invalid input, shouldn't happen")
	}

	token := params[0]
	s.rcptTo = params[1]

	if s.ok {
		fmt.Fprintf(os.Stderr, "session is whitelisted\n")
		fmt.Printf("filter-result|%s|%s|proceed\n", token, s.id)
		return
	}

	key := fmt.Sprintf("ip=%s", s.ip.String())
	if val, ok := whitelist_src[key]; ok {
		if s.tm - val < *whiteexp {
			fmt.Fprintf(os.Stderr, "IP address %s is whitelisted\n", s.ip.String())
			fmt.Printf("filter-result|%s|%s|proceed\n", token, s.id)
			whitelist_src[key] = s.tm
			return
		}
	}

	key = fmt.Sprintf("domain=%s", s.fromDomain)
	if val, ok := whitelist_domain[key]; ok {
		if s.tm - val < *whiteexp {
			fmt.Fprintf(os.Stderr, "domain %s is whitelisted\n", s.fromDomain)
			fmt.Printf("filter-result|%s|%s|proceed\n", token, s.id)
			whitelist_domain[key] = s.tm
			return
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
		if val, ok := greylist_src[key]; ok {
			delta := s.tm - val
			if val != s.tm && delta < *greyexp && delta > *passtime {
				fmt.Fprintf(os.Stderr, "IP %s added to whitelist\n", s.ip.String())
				fmt.Printf("filter-result|%s|%s|proceed\n", token, s.id)
				key = fmt.Sprintf("ip=%s", s.ip.String())
				whitelist_src[key] = s.tm
				s.ok = true
				return
			}
		} else {
			fmt.Fprintf(os.Stderr, "IP %s added to greylist\n", s.ip.String())
		}
		greylist_src[key] = s.tm
		fmt.Printf("filter-result|%s|%s|reject|451 greylisted, try again later\n", token, s.id)
		return
	}		

	key := fmt.Sprintf("domain=%s:%s:%s", s.fromDomain, s.mailFrom, s.rcptTo)
	if val, ok := greylist_domain[key]; ok {
		delta := s.tm - val
		if val != s.tm && delta < *greyexp && delta > *passtime {
			fmt.Fprintf(os.Stderr, "domain %s added to whitelist\n", s.fromDomain)
			fmt.Printf("filter-result|%s|%s|proceed\n", token, s.id)
			key = fmt.Sprintf("domain=%s", s.fromDomain)
			whitelist_domain[key] = s.tm
			s.ok = true
			return
		}
	} else {
		fmt.Fprintf(os.Stderr, "domain %s added to greylist\n", s.fromDomain)
	}
	greylist_domain[key] = s.tm
	fmt.Printf("filter-result|%s|%s|reject|451 greylisted, try again later\n", token, s.id)
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

func main() {
	passtime  = flag.Int64("passtime", 300, "number of seconds before retries are accounted (default: 300)")
	greyexp   = flag.Int64("greyexp", 4*3600, "number of seconds before greylist attempts expire (default: 4 hours)")
	whiteexp  = flag.Int64("whiteexp", 30*86400, "number of seconds before whitelists expire (default: 30 days)")
	ip_wl     = flag.String("wl-ip", "", "filename containing a list of IP addresses to whitelist, one per line")
	domain_wl = flag.String("wl-domain", "", "filename containing a list of sender domains to whitelist, one per line")

	flag.Parse()

	loadWhitelists()

	scanner := bufio.NewScanner(os.Stdin)

	skipConfig(scanner)

	filterInit()

	for {
		if !scanner.Scan() {
			os.Exit(0)
		}

		atoms := strings.Split(scanner.Text(), "|")
		if len(atoms) < 6 {
			os.Exit(1)
		}

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
