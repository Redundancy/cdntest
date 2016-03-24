/*
CDN Test is a program intended to be distributed to the users of a service,
in order to help debug connection issues to a CDN (which frequently seem to
involve ISPs with congested routes)

It is currently based mainly around the debugging of CloudFront requests,
which helpfully already provide a source of helpful information:
http://d7uri8nf7uskq.cloudfront.net/CustomerTesting.html

Rather than require a user to be quite technically competent and install or use
multiple tools, cdntest aims to reduce the work required by the end user to
downloading a single tool, and running it with an endpoint file to download,
then producing output in a file (and on the console) that the user can attach
to a report.
*/
package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/codegangsta/cli"
)

var transport = &http.Transport{
	Proxy: http.ProxyFromEnvironment,
	ResponseHeaderTimeout: time.Second * 10,
}

// Use a custom http client to ensure sensible timeouts
var DefaultClient = &http.Client{
	Timeout:   10 * time.Second,
	Transport: transport,
}

func getPort(scheme string) (int, error) {
	switch scheme {
	case "http":
		return 80, nil
	case "https":
		return 443, nil
	default:
		return 0, fmt.Errorf("Expected http or https: \"%v\"", scheme)
	}
}

func getMyPublicIP() (string, error) {
	response, err := DefaultClient.Get("https://api.ipify.org")

	if err != nil {
		return "", fmt.Errorf(
			"Could not contact https://api.ipify.org to get your public IP: %v",
			err,
		)
	}

	defer response.Body.Close()

	b, err := ioutil.ReadAll(response.Body)

	if err != nil {
		return "", fmt.Errorf(
			"Could not contact https://api.ipify.org to get your public IP: %v",
			err,
		)
	}

	return string(b), nil
}

func main() {
	app := cli.NewApp()
	app.Author = "Daniel Robert Speed"
	app.Usage = `
	Used for testing HTTP(S) endpoints for their SSL certificates and performance.

	See: https://github.com/Redundancy/cdntest
	`
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "ip",
			Usage: "Use an explicit IP address rather than DNS provided",
		},
		cli.StringFlag{
			Name:  "cname",
			Usage: "Use an alternative DNS entry to lookup the IP",
		},
	}

	app.Action = func(c *cli.Context) {
		if c.NArg() != 1 {
			return
		}

		testHTTP(options{
			url:   c.Args()[0],
			ip:    c.String("ip"),
			cname: c.String("cname"),
		})
	}

	app.Run(os.Args)
}

type options struct {
	url   string
	ip    string
	cname string
}

func testHTTP(o options) {
	cdnURL, err := url.Parse(o.url)

	if err != nil {
		fmt.Printf("Could not parse url: \"%v\" - %v\n", cdnURL, err)
		os.Exit(1)
	}

	port, err := getPort(cdnURL.Scheme)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println("Running CDN test at", time.Now())
	myPublicIP, err := getMyPublicIP()

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println("My public IP is:", myPublicIP)

	var addrs []string

	host := cdnURL.Host
	if o.cname != "" {
		host = o.cname
	}

	beforeLookup := time.Now()
	addrs, err = net.LookupHost(host)
	fmt.Printf("Host lookup of %v took %v\n", host, time.Now().Sub(beforeLookup))

	if err != nil {
		fmt.Println("Could not look up host:", err)
		os.Exit(1)
	}

	fmt.Println("DNS returned:", addrs)

	/*
		resolver-identity.cloudfront.net reflects back the IP of the dns server that
		looked it up.
	*/
	resolverIdentities, _ := net.LookupHost("resolver-identity.cloudfront.net")
	if len(resolverIdentities) > 0 {
		resolverNames, _ := net.LookupAddr(resolverIdentities[0])

		fmt.Printf(
			"Your DNS resolver is %v (%v)\n",
			resolverNames[0],
			resolverIdentities[0],
		)
	} else {
		fmt.Printf("Could not identify your DNS resolver\n")
	}

	request, _ := http.NewRequest("GET", cdnURL.String(), nil)

	// We cannot use http.Transport because it does not provide hooks
	// to get the timing metrics that we require
	// TODO: Proxy support based on environment variables
	var conn net.Conn
	var dialErr error

	ip := addrs[0]
	if o.ip != "" {
		ip = o.ip
	}

	beforeDialTime := time.Now()
	conn, dialErr = net.DialTimeout(
		"tcp",
		fmt.Sprintf("%v:%v", ip, port),
		10*time.Second,
	)
	afterDialTime := time.Now()

	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()

	if dialErr != nil {
		fmt.Println("Could not contact server:", dialErr)
		os.Exit(1)
	}

	fmt.Println(
		"Connected to",
		conn.RemoteAddr().String(),
		"in",
		afterDialTime.Sub(beforeDialTime),
	)

	if cdnURL.Scheme == "https" {
		config := &tls.Config{
			ServerName: cdnURL.Host,
		}

		beforeHandshakeTime := time.Now()
		tlsCon := tls.Client(conn, config)
		tlsCon.SetDeadline(time.Now().Add(10 * time.Second))
		if hsErr := tlsCon.Handshake(); hsErr != nil {
			fmt.Println("SSL handshake error:", hsErr)
		}
		fmt.Println("TLS handshake in", time.Now().Sub(beforeHandshakeTime))

		if e := tlsCon.VerifyHostname(cdnURL.Host); e != nil {
			fmt.Println("SSL was unable to verify the hostname!", e)
		}

		printableCertChain(tlsCon.ConnectionState().PeerCertificates).Write(os.Stdout)

		conn = tlsCon
	}

	request.WriteProxy(conn)
	beforeRead := time.Now()
	response, err := http.ReadResponse(bufio.NewReader(conn), request)

	if err != nil || response == nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			fmt.Println(
				"Timeout reading response from",
				cdnURL.String(),
			)
		} else {
			fmt.Println(
				"Did not get a response (after establishing connection),",
				"server behind loadbalancer / CDN may be down:",
				err,
			)
		}
		os.Exit(1)
	}

	if response.Body != nil {
		defer response.Body.Close()
	}

	if response.Body != nil {
		b, _ := ioutil.ReadAll(response.Body)
		timeTaken := time.Now().Sub(beforeRead)
		bps := bytesPerSecond((float64(time.Second) / float64(timeTaken)) * float64(len(b)))

		fmt.Printf(
			"Reading %v bytes took %v (%v)\n",
			len(b), //response.Header.Get("content-length"),
			timeTaken,
			bps,
		)
	}

	if response.Header.Get("X-Amz-Cf-Id") != "" {
		fmt.Println("Amazon CloudFront Request ID:", response.Header.Get("X-Amz-Cf-Id"))

		// lookup AWS DNS server
		nameserver, _ := net.LookupHost("identity.cloudfront.net")
		names, _ := net.LookupAddr(nameserver[0])

		fmt.Printf(
			"The CloudFront DNS server you query is %v (%v)\n",
			names[0],
			nameserver[0],
		)
	}
}

type printableCertChain []*x509.Certificate

func (cc printableCertChain) Write(o io.Writer) {
	fmt.Fprintln(o, "SSL Certificate Information")

	for _, cert := range cc {
		if cert.IsCA {
			fmt.Fprintf(
				o,
				"\t%v - Valid Until: %v\n",
				cert.Subject.CommonName,
				cert.NotAfter,
			)
		} else {
			fmt.Fprintf(
				o,
				"\t%v - Issued by: %v, Valid Until: %v\n",
				cert.Subject.CommonName,
				cert.Issuer.CommonName,
				cert.NotAfter,
			)
		}
	}

}

type bytesPerSecond int64

func (i bytesPerSecond) String() string {
	switch {
	case i < 1000:
		return fmt.Sprintf("%v bytes/s", int64(i))
	case i < 1000*1000:
		return fmt.Sprintf("%v KiB/s", int64(i)/1000)
	default:
		return fmt.Sprintf("%v MiB/s", int64(i)/1000000)
	}
}
