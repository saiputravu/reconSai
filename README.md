# reconSai

## Table of Contents

* [About the Project](#about-the-project)
* [Main Features](#main-features)
* [Installation](#installation)
* [Usage](#usage)

## About The Project
This is a hobby project I created in order to bring all the recon tools together into one place. The main code is written in pure bash so prepare to feast your eyes upon lines upon lines of disgusting one-liners, janky code and hardcoded values!

## Main Features
I tried making this code as portable as possible, but only have tested on Ubuntu and Kali. The tools are not regularly updated and some potentially may be out of date at the time of installation (fully updated as of 2021).

### Key Features:
* Reconnaissance script
    - Subdomain discovery (passive and active)
    - Portscanning (masscan -> nmap)
    - Screenshotting & subdomain mapping
    - Page crawling
    - Detecting new subdomains
    - Finding javascript links
    - Wayback machine crawling
    - Basic url parameter scanning
    - Basic shodan integration
* Scheduling script
    - Checks and updates a file for new subdomains
    - Run it as a cronjob and give it a list of targets

### Features yet-to-be-implemented (when I am free):
* Reconnaissance script
    - Interactive javascript website w/ database management for output
    - Github scanning (trufflehog & gitRob)
    - S3 bucket scanning / GCP & Azure later
    - Automatic subdomain bruteforcing (need a better wordlist)
    - Automatic path bruteforcing (also need a better wordlist for this)
* Scheduling script
    - Updates via social media / email
    - Better integration with daily life

## Installation

Installation is as simple as 
```bash
git clone https://github.com/saiputravu/reconSai.git
cd reconSai
./install.sh
cd ..
```

Most, if not all tools are symlinked so no path is required.
Tool Locations: ~/reconTools

## Usage

### scheduler.sh
You have to supply a list of targets.txt. These should take the format of 
```
a.domain.com /path/to/a.domain.com_output_dir
b.domain.com /path/to/b.domain.com_output_dir
...
```

### reconSai
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



