package main

import (
	_ "github.com/mattn/go-sqlite3"
	"github.com/miekg/dns"
	"database/sql"
	"sync"
	"net"
	"log"
)

type Record struct {
	key   string
	rtype int
	value string
}

func orPanic(err error) {
	if err != nil {
		log.Fatalf("Fatal error: %v\n", err)
	}
}

func cidr(s string) net.IPNet {
	_, ipnet, err := net.ParseCIDR(s)
	orPanic(err)
	return *ipnet
}


func isCloudflare(ip net.IP) bool {
	for _, ipnet := range cloudflareRanges {
		if ipnet.Contains(ip) {
			return true
		}
	}
	return false
}

func nextHost(db *sql.DB, count *int) ([]Record, bool) {
	rows, err := db.Query(`
		SELECT h.host, a.value
		FROM hosts h
		INNER JOIN rrs ns ON (h.host = ns.key AND ns.type = 2)
		INNER JOIN rrs a ON (ns.value = a.key AND a.type = 1)
		WHERE NOT h.is_checked
		LIMIT 100 OFFSET ?
	`, count)
	orPanic(err)
	defer rows.Close()

	var records []Record
	for rows.Next() {
		*count++

		var key, value string
		rows.Scan(&key, &value)
		records = append(records, Record{key, 2, value})
	}

	if len(records) <= 0 {
		log.Println("No more rows")
	}

	return records, len(records) <= 0
}

func writeResult(db *sql.DB, rr Record) {
	touch := true
	var err error

	if rr.rtype >= 0 {
		_, err = db.Exec(`
			INSERT OR IGNORE INTO rrs
			(source_id, key, type, value)
			VALUES (2, ?, ?, ?)
		`, rr.key, rr.rtype, rr.value)
		orPanic(err)

		if rr.rtype == 1 || rr.rtype == 28 {
			if ip := net.ParseIP(rr.value); ip != nil && isCloudflare(ip) {
				log.Println("Found host with CF IP:", rr.key, ip.String())

				_, err = db.Exec(`
					INSERT OR IGNORE INTO ips
					(ip, source_id, is_cf)
					VALUES (?, ?, ?)
				`, ip.String(), 2, 1)
				orPanic(err)

				_, err = db.Exec(`
					UPDATE hosts
					SET has_cf_ip = 1, is_checked = 1
					WHERE host = ?
				`, rr.key)
				orPanic(err)

				touch = false
			}
		}
	}

	if touch {
		_, err = db.Exec(`
			UPDATE hosts
			SET is_checked = 1
			WHERE host = ?
		`, rr.key)
	}
}

func runDB(db *sql.DB, hosts chan Record, results chan Record) {
	log.Println("Entering runDB")
	count := 0

	var pendingHostIdx int
	var pendingHost Record
	pendingHosts, eof := nextHost(db, &count)
	if eof {
		log.Println("EOF; closing hosts channel (1)")
		pendingHost = CLOSED
		close(hosts)
	} else {
		pendingHostIdx = 0
		pendingHost = pendingHosts[pendingHostIdx]
		log.Println("Next host:", pendingHost, "(1)")
	}

	log.Println("runDB loop")
	for {
		select {
		case hosts <- pendingHost:
			if !eof {
				pendingHostIdx++
				if pendingHostIdx >= len(pendingHosts) {
					pendingHosts, eof = nextHost(db, &count)
					if eof {
						log.Println("EOF; closing hosts channel (2)")
						pendingHost = CLOSED
						close(hosts)
					} else {
						pendingHostIdx = 0
					}
				}
				if !eof {
					pendingHost = pendingHosts[pendingHostIdx]
					log.Println("Next host:", pendingHost, "(2)")
				}
			}

		case rr := <-results:
			writeResult(db, rr)
		}
	}

	log.Println("Exiting runDB")
}

func runDNS(hosts chan Record, results chan Record) {
	log.Println("Entering runDNS")

	c := new(dns.Client)

	for host := range hosts {
		name := host.key
		ns := host.value
		log.Println("Running DNS lookup on", name, "via", ns)

		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(host.key), dns.TypeA)
		msg.RecursionDesired = false

		r, _, err := c.Exchange(msg, net.JoinHostPort(ns, "53"))
		if err != nil || r == nil {
			log.Printf("DNS lookup error for %s: %s\n", name, err.Error())
			continue
		}

		touch := true

		if r.Rcode != dns.RcodeSuccess {
			log.Printf("Invalid DNS rcode for %s: %d\n", name, r.Rcode)
		} else if len(r.Answer) <= 0 {
			log.Printf("Got no answers for %s\n", name)
		} else {
			for _, rr := range r.Answer {
				header := rr.Header()
				result := Record{name, int(header.Rrtype), ""}

				switch header.Rrtype {
				case  1: result.value = rr.(*dns.A).A.String()
				case 28: result.value = rr.(*dns.AAAA).AAAA.String()
				case  5: result.value = rr.(*dns.CNAME).String()
				case 39: result.value = rr.(*dns.DNAME).String()
				}

				if len(result.value) > 0 {
					touch = false
					results <- result
				}

				log.Printf("Answer for %s: %v\n", name, rr);
			}
		}

		if touch {
			results <- TOUCH
		}
	}

	log.Println("Exiting runDNS")
}

func main() {
	db, err := sql.Open("sqlite3", "cf.db")
	orPanic(err)
	defer db.Close()

	hosts := make(chan Record, 100)
	results := make(chan Record, 8)

	var wg sync.WaitGroup
	log.Println("Starting")

	wg.Add(1)
	go func() {
		defer wg.Done()
		runDB(db, hosts, results)
	}()

	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runDNS(hosts, results)
		}()
	}

	wg.Wait()
	log.Println("Done")
}

var(
	CLOSED = Record{rtype: -1}
	TOUCH  = Record{rtype: -2}
	cloudflareRanges = []net.IPNet{
		cidr("103.21.244.0/22"),
		cidr("103.22.200.0/22"),
		cidr("103.31.4.0/22"),
		cidr("104.16.0.0/12"),
		cidr("108.162.192.0/18"),
		cidr("131.0.72.0/22"),
		cidr("141.101.64.0/18"),
		cidr("162.158.0.0/15"),
		cidr("172.64.0.0/13"),
		cidr("173.245.48.0/20"),
		cidr("188.114.96.0/20"),
		cidr("190.93.240.0/20"),
		cidr("197.234.240.0/22"),
		cidr("198.41.128.0/17"),
		cidr("199.27.128.0/21"),
		cidr("2400:cb00::/32"),
		cidr("2405:8100::/32"),
		cidr("2405:b500::/32"),
		cidr("2606:4700::/32"),
		cidr("2803:f800::/32"),
		cidr("2c0f:f248::/32"),
		cidr("2a06:98c0::/29"),
	}
)
