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
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("cdntest must be called with a url")
		os.Exit(1)
	}

	urlArg := os.Args[1]

	cdnURL, err := url.Parse(urlArg)
	if err != nil {
		fmt.Printf("Could not parse url: \"%v\" - %v\n", cdnURL, err)
		os.Exit(1)
	}

	port := 80
	switch cdnURL.Scheme {
	case "http":
	case "https":
		port = 443
	default:
		fmt.Printf("Expected http or https url: \"%v\"\n", urlArg)
		os.Exit(1)
	}

	fmt.Println("Running CDN test at", time.Now())

	if r, getErr := http.Get("https://api.ipify.org"); getErr == nil {
		defer r.Body.Close()
		if b, e := ioutil.ReadAll(r.Body); e == nil {
			fmt.Println("Your public IP is", string(b))
		}
	} else {
		fmt.Println("Could not contact https://api.ipify.org to get your public IP")
	}

	var addrs []string

	beforeLookup := time.Now()
	addrs, err = net.LookupHost(cdnURL.Host)
	fmt.Printf("Host lookup of %v took %v\n", cdnURL.Host, time.Now().Sub(beforeLookup))
	if err != nil {
		fmt.Println("Could not look up host:", err)
	}

	/*
		resolver-identity.cloudfront.net reflects back the IP of the dns server that
		looked it up.
	*/
	resolverIdentities, _ := net.LookupHost("resolver-identity.cloudfront.net")
	resolverNames, _ := net.LookupAddr(resolverIdentities[0])

	fmt.Printf(
		"Your DNS resolver is %v (%v)\n",
		resolverNames[0],
		resolverIdentities[0],
	)

	request, _ := http.NewRequest("GET", cdnURL.String(), nil)

	// We cannot use http.Transport because it does not provide hooks
	// to get the timing metrics that we require
	// TODO: Proxy support based on environment variables
	var conn net.Conn
	var dialErr error

	beforeDialTime := time.Now()
	conn, dialErr = net.Dial("tcp", fmt.Sprintf("%v:%v", addrs[0], port))
	afterDialTime := time.Now()

	defer conn.Close()

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
	response, _ := http.ReadResponse(bufio.NewReader(conn), request)

	if response.Body != nil {
		defer response.Body.Close()
	}

	if response.Body != nil {
		b, _ := ioutil.ReadAll(response.Body)
		timeTaken := time.Now().Sub(beforeRead)
		bps := bytesPerSecond((float64(time.Second) / float64(timeTaken)) * float64(len(b)))

		fmt.Printf(
			"Reading %v bytes took %v (%v)\n",
			response.Header.Get("content-length"),
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
