# cdntest

CDN Test is a program intended to be distributed to the users of a service,
in order to help debug connection issues to a CDN.

It is currently based mainly around the debugging of CloudFront requests,
which helpfully already provide a source of helpful information:
http://d7uri8nf7uskq.cloudfront.net/CustomerTesting.html

Rather than require a user to be quite technically competent and install or use
multiple tools, cdntest aims to reduce the work required by the end user to
downloading a single tool, and running it with an endpoint file to download,
then producing output in a file (and on the console) that the user can attach
to a report.

## Usage
You will require a test url to use.

`cdntest http://d7uri8nf7uskq.cloudfront.net/sample.jpg`

```
Running CDN test at 2016-01-31 22:23:42.999998 +0000 GMT
Your public IP is ??.???.??.???
Host lookup of d7uri8nf7uskq.cloudfront.net took 1.0041ms
Your DNS resolver is ns1.internet.is (213.176.128.51)
Connected to 54.192.198.113:80 in 50.7838ms
Reading 68886 bytes took 206.4187ms (333 KiB/s)
Amazon CloudFront Request ID: z9OebyMqisgcMFVmXcd0UqFO8_2mKLtkwWYr58QJC5YApYRXjlRYCQ==
The CloudFront DNS server you query is server-216-137-58-23.ams1.r.cloudfront.net (216.137.58.23)
```

## Features Still Needed
- [ ] Follow Redirects
- [ ] Use Proxy environment variables
- [ ] Directly comparable to cUrl timing variables: http://curl.haxx.se/docs/manpage.html

## Information Provided
- [x] Test Timestamp
- [x] User's public IP address (via https://api.ipify.org)
- [x] AWS CloudFront - DNS Identity
- [x] AWS CloudFront - Request ID
- [x] DNS resolver (via resolver-identity.cloudfront.net)
- [x] Endpoint IP
- [x] TCP connection time
- [x] SSL Handshake time
- [x] SSL Certificate validation
- [x] Download time
- [ ] Number of redirects
- [ ] Packet loss
- [ ] Traceroute
