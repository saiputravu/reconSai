# reconSai

## Table of Contents

* [About the Project](#about-the-project)
* [Installation](#installation)
* [Usage](#usage)


## About The Project

## Installation

## Usage
```
Example usage: /usr/local/bin/reconSai -d domain.com [options]
               /usr/local/bin/reconSai -d domain.com --all
               /usr/local/bin/reconSai -e [options]
               /usr/local/bin/reconSai -e -S count apache
               /usr/local/bin/reconSai -e -M ./domains-wildcards.txt -d domain.com

        --all                                   Run everything                                                  [active AND passive]

        -d|--domain <domain>                    Domain to recon                                                 [active]
        -n|--nmap                               Allow portscanning                                              [active]
        -m|--massdns                            Allow DNS queries                                               [active]
        -s|--screenshot                         Allow screenshotting                                            [active]
        -l|--linkfinder                         Check domain js files                                           [active]
        -M|--monitor <domains-wildcard.txt>     Run monitor mode (pass previously discovered domains.txt)       [passive]
        -c|--crawl                              Allow searching repos to get previous urls discovered           [passive]
        -g|--gf                                 Search through the waybackurls.txt file for vulnerabilities     [passive]
        -S|--shodan <ip|query|count> <string>   Run a shodan query or ip or just get summary                    [passive]
        -a|--noalive                            Disable checking alive subdomains (note can't run other active) [passive-only]

        -q|--quiet                              Don't print banners
        -e|--extra                              Only run non-main features
        -G|--github                             Print some github dork links to try out

Other stuff to check out:
        * TXT,CNAME,MX Records
        * Subdomain takeover
        * https://raw.githubusercontent.com/sushiwushi/bug-bounty-dorks/master/dorks.txt

        * S3 Buckets
                - site:s3.amazonaws.com query (google)
        * Github recon
                - truffleHog
                - gitRob
        * Trello
                - site:trello.com intext:ftp (...etc) (google)
        * amass active
                - amass enum -rf /opt/my-lists/resolvers -nf domains.txt -v -ip -active -min-for-recursive 3 -df root-domains -o output-subdomains.txt
        * Websites
                - spyonweb.com - Google Analytics
```
