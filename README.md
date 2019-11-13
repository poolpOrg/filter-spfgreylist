# filter-greylist

## Description
This filter implements greylisting, allowing OpenSMTPD to temporarily reject sessions of
clients it has not seen before to check if they come from a real MX rather than scripts.


## Features
The filter currently supports:

- SPF-aware greylisting



## Dependencies
The filter is written in Golang and doesn't have any dependencies beyond standard library.

It requires OpenSMTPD 6.6.0 or higher.


## How to install
Install from your operating system's preferred package manager if available.
On OpenBSD:
```
$ doas pkg_add opensmtpd-filter-greylisting
quirks-3.167 signed on 2019-08-11T14:18:58Z
opensmtpd-filter-greylisting-0.1.x: ok
$
```

Alternatively, clone the repository, build and install the filter:
```
$ cd filter-greylisting/
$ go build
$ doas install -m 0555 filter-greylist /usr/local/libexec/smtpd/filter-greylist
```


## How to configure
The filter itself requires no configuration.

It must be declared in smtpd.conf and attached to a listener for sessions to go through greylisting:
```
filter "greylist" proc-exec "filter-greylist"

listen on all filter "greylist"
```
