# filter-spfgreylist

## Description
This filter implements greylisting, allowing OpenSMTPD to temporarily reject sessions of
clients it has not seen before. Unlike many implementations, this one is SPF-aware so it
will properly handle greylisting for domains doing relaying through multiple MX, as long
as they publish a valid SPF record.

**This initial version is a proof of concept, it does not persist state outside of memory, and might suffer from bugs.**

**Do not use in production (yet).**


## Features
The filter currently supports:

- IPv4 and IPv6 address greylisting
- SPF greylisting
- startup whitelisting of IP and domains
- automatically renewed whitelisting


## Dependencies
The filter is written in Golang and doesn't have any dependencies beyond standard library.

It requires OpenSMTPD 6.6.0 or higher.


## How to install
Clone the repository, build and install the filter:
```
$ cd filter-spfgreylist/
$ go build
$ doas install -m 0555 filter-spfgreylist /usr/local/libexec/smtpd/filter-spfgreylist
```


## How to configure
The filter itself requires no configuration.

It must be declared in smtpd.conf and attached to a listener for sessions to go through greylisting:
```
filter "greylist" proc-exec "filter-spfgreylist"

listen on all filter "greylist"
```

It is possible to tweak the greylisting parameters, here listed with default values:

- `-passtime 5m` accept greylisting retries only after 5 minutes from initial attempt
- `-greyexp 4h` expire greylisting attempts after 4 hours without a retry
- `-whiteexp 720h` expire whitelisting after 30 days without any attempt at delivery

Valid time units are "s", "m" and "h".

It is also possible to inject IP and domains in the whitelists at startup to avoid greylisting:

- `-wl-ip <filename>` inject IP addresses listed, one per line, in the parameter file to the whitelist
- `-wl-domain <filename>` inject domains listed, one per line, in the parameter file to the whitelist
