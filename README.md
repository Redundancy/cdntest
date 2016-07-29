# cdntest

CDN Test is a program intended to be able to be distributed to the users of a service,
in order to help debug connection issues to a CDN. It provides a large amount of
connection timing information, as well as DNS and the IP to which it connected.
It also allows advanced users to specify an IP or DNS that will override the hostname in the URL,
enabling you to test connections to CDN distributions without changing your hosts file or DNS entries.

It is currently based mainly around the debugging of CloudFront requests,
which helpfully already provide a source of helpful information:
http://d7uri8nf7uskq.cloudfront.net/CustomerTesting.html

Rather than require a user to be quite technically competent and install or use
multiple tools, cdntest aims to reduce the work required by the end user to
downloading a single tool, and running it with an endpoint file to download,
then producing output in a file (and on the console) that the user can attach
to a report.

## Usage

```
> cdntest https://www.google.com
Running CDN test at 2016-07-28 20:40:06.3299465 -0400 EDT
My public IP is: xxx.xxx.xxx.xxx
Host lookup of www.google.com took 14.6991ms
DNS returned: [173.194.219.105 173.194.219.104 173.194.219.99 173.194.219.106 173.194.219.103 173.194.219.147]
Your DNS resolver is  (71.242.0.216)
Connected to 173.194.219.105:443 in 32.0209ms
TLS handshake in 67.0429ms
SSL Certificate Information
        www.google.com - Issued by: Google Internet Authority G2, Valid Until: 2016-10-05 13:16:00 +0000 UTC
        Google Internet Authority G2 - Valid Until: 2017-12-31 23:59:59 +0000 UTC
        GeoTrust Global CA - Valid Until: 2018-08-21 04:00:00 +0000 UTC
Response was 200 OK
Reading 10487 bytes took 50.6795ms (206 KiB/s)
MD5 of Content fda603052f13608c0364ed8f71e5e50c
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
- [x] MD5 Hash of content
- [x] Response Code Status
- [x] Save the content body to file
- [ ] Number of redirects
- [ ] Packet loss
- [ ] Traceroute
