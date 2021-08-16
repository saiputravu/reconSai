#!/bin/bash
red=`tput setaf 1`
green=`tput setaf 2`
yellow=`tput setaf 3`
blue=`tput setaf 4`
purple=`tput setaf 5`
cyan=`tput setaf 6`
reset=`tput sgr0`

# Defined in reconSai script
# TOOLSDIR=~/reconTools

domain_github_dorks () {
	if [ "$#" -ne 1 ]; then
		echo "${red}Usage: domain_github_dorks <domains>${reset}"
		return
	fi
	echo ""
	echo "************ Github Dork Links (must be logged in) *******************"
	echo ""
	echo "  password"
	echo "https://github.com/search?q=%22$1%22+password&type=Code"
	echo "https://github.com/search?q=%22$without_suffix%22+password&type=Code"
	echo ""
	echo " npmrc _auth"
	echo "https://github.com/search?q=%22$1%22+npmrc%20_auth&type=Code"
	echo "https://github.com/search?q=%22$without_suffix%22+npmrc%20_auth&type=Code"
	echo ""
	echo " dockercfg"
	echo "https://github.com/search?q=%22$1%22+dockercfg&type=Code"
	echo "https://github.com/search?q=%22$without_suffix%22+dockercfg&type=Code"
	echo ""
	echo " pem private"
	echo "https://github.com/search?q=%22$1%22+pem%20private&type=Code"
	echo "https://github.com/search?q=%22$without_suffix%22+extension:pem%20private&type=Code"
	echo ""
	echo "  id_rsa"
	echo "https://github.com/search?q=%22$1%22+id_rsa&type=Code"
	echo "https://github.com/search?q=%22$without_suffix%22+id_rsa&type=Code"
	echo ""
	echo " aws_access_key_id"
	echo "https://github.com/search?q=%22$1%22+aws_access_key_id&type=Code"
	echo "https://github.com/search?q=%22$without_suffix%22+aws_access_key_id&type=Code"
	echo ""
	echo " s3cfg"
	echo "https://github.com/search?q=%22$1%22+s3cfg&type=Code"
	echo "https://github.com/search?q=%22$without_suffix%22+s3cfg&type=Code"
	echo ""
	echo " htpasswd"
	echo "https://github.com/search?q=%22$1%22+htpasswd&type=Code"
	echo "https://github.com/search?q=%22$without_suffix%22+htpasswd&type=Code"
	echo ""
	echo " git-credentials"
	echo "https://github.com/search?q=%22$1%22+git-credentials&type=Code"
	echo "https://github.com/search?q=%22$without_suffix%22+git-credentials&type=Code"
	echo ""
	echo " bashrc password"
	echo "https://github.com/search?q=%22$1%22+bashrc%20password&type=Code"
	echo "https://github.com/search?q=%22$without_suffix%22+bashrc%20password&type=Code"
	echo ""
	echo " sshd_config"
	echo "https://github.com/search?q=%22$1%22+sshd_config&type=Code"
	echo "https://github.com/search?q=%22$without_suffix%22+sshd_config&type=Code"
	echo ""
	echo " xoxp OR xoxb OR xoxa"
	echo "https://github.com/search?q=%22$1%22+xoxp%20OR%20xoxb%20OR%20xoxa&type=Code"
	echo "https://github.com/search?q=%22$without_suffix%22+xoxp%20OR%20xoxb&type=Code"
	echo ""
	echo " SECRET_KEY"
	echo "https://github.com/search?q=%22$1%22+SECRET_KEY&type=Code"
	echo "https://github.com/search?q=%22$without_suffix%22+SECRET_KEY&type=Code"
	echo ""
	echo " client_secret"
	echo "https://github.com/search?q=%22$1%22+client_secret&type=Code"
	echo "https://github.com/search?q=%22$without_suffix%22+client_secret&type=Code"
	echo ""
	echo " sshd_config"
	echo "https://github.com/search?q=%22$1%22+sshd_config&type=Code"
	echo "https://github.com/search?q=%22$without_suffix%22+sshd_config&type=Code"
	echo ""
	echo " github_token"
	echo "https://github.com/search?q=%22$1%22+github_token&type=Code"
	echo "https://github.com/search?q=%22$without_suffix%22+github_token&type=Code"
	echo ""
	echo " api_key"
	echo "https://github.com/search?q=%22$1%22+api_key&type=Code"
	echo "https://github.com/search?q=%22$without_suffix%22+api_key&type=Code"
	echo ""
	echo " FTP"
	echo "https://github.com/search?q=%22$1%22+FTP&type=Code"
	echo "https://github.com/search?q=%22$without_suffix%22+FTP&type=Code"
	echo ""
	echo " app_secret"
	echo "https://github.com/search?q=%22$1%22+app_secret&type=Code"
	echo "https://github.com/search?q=%22$without_suffix%22+app_secret&type=Code"
	echo ""
	echo "  passwd"
	echo "https://github.com/search?q=%22$1%22+passwd&type=Code"
	echo "https://github.com/search?q=%22$without_suffix%22+passwd&type=Code"
	echo ""
	echo " s3.yml"
	echo "https://github.com/search?q=%22$1%22+.env&type=Code"
	echo "https://github.com/search?q=%22$without_suffix%22+.env&type=Code"
	echo ""
	echo " .exs"
	echo "https://github.com/search?q=%22$1%22+.exs&type=Code"
	echo "https://github.com/search?q=%22$without_suffix%22+.exs&type=Code"
	echo ""
	echo " beanstalkd.yml"
	echo "https://github.com/search?q=%22$1%22+beanstalkd.yml&type=Code"
	echo "https://github.com/search?q=%22$without_suffix%22+beanstalkd.yml&type=Code"
	echo ""
	echo " deploy.rake"
	echo "https://github.com/search?q=%22$1%22+deploy.rake&type=Code"
	echo "https://github.com/search?q=%22$without_suffix%22+deploy.rake&type=Code"
	echo ""
	echo " mysql"
	echo "https://github.com/search?q=%22$1%22+mysql&type=Code"
	echo "https://github.com/search?q=%22$without_suffix%22+mysql&type=Code"
	echo ""
	echo " credentials"
	echo "https://github.com/search?q=%22$1%22+credentials&type=Code"
	echo "https://github.com/search?q=%22$without_suffix%22+credentials&type=Code"
	echo ""
	echo " PWD"
	echo "https://github.com/search?q=%22$1%22+PWD&type=Code"
	echo "https://github.com/search?q=%22$without_suffix%22+PWD&type=Code"
	echo ""
	echo " deploy.rake"
	echo "https://github.com/search?q=%22$1%22+deploy.rake&type=Code"
	echo "https://github.com/search?q=%22$without_suffix%22+deploy.rake&type=Code"
	echo ""
	echo " .bash_history"
	echo "https://github.com/search?q=%22$1%22+.bash_history&type=Code"
	echo "https://github.com/search?q=%22$without_suffix%22+.bash_history&type=Code"
	echo ""
	echo " .sls"
	echo "https://github.com/search?q=%22$1%22+.sls&type=Code"
	echo "https://github.com/search?q=%22$without_suffix%22+PWD&type=Code"
	echo ""
	echo " secrets"
	echo "https://github.com/search?q=%22$1%22+secrets&type=Code"
	echo "https://github.com/search?q=%22$without_suffix%22+secrets&type=Code"
	echo ""
	echo " composer.json"
	echo "https://github.com/search?q=%22$1%22+composer.json&type=Code"
	echo "https://github.com/search?q=%22$without_suffix%22+composer.json&type=Code"
	echo ""

}

domain_alive_check () {
	if [ "$#" -ne 1 ]; then
		echo "${red}Usage: domain_alive_check <domains.txt>${reset}"
		return
	fi
	# Alive check
	[ ! -d temp ] && mkdir temp
	echo -e "${blue}[*] ${yellow}Checking alive subdomains${reset}"
	echo -e "${blue}[?] ${yellow}Fuff output: \n${reset}"
	ffuf -w $1 -u "http://FUZZ" -o temp/ffuf-check.txt -of md > /dev/null
	echo
	cat temp/ffuf-check.txt | grep -e 301 -e 200 -e 403 -e 204 -e 302 -e 307 -e 401 | cut -d'|' -f2 | tr -d ' ' > alive-domains.txt
	
}

domain_linkfinder () {
	if [ "$#" -ne 1 ]; then
		echo "${red}Usage: domain_linkfinder <domain>"
		return
	fi

	# Hard coded paths
	echo -e "${blue}[*] ${yellow}Checking js tings in $1\n${reset}"
	mkdir linkfinder
	linkfinder -d -i "http://$1" -o linkfinder/linkfinder-report-http.html 2>/dev/null
	linkfinder -d -i "https://$1" -o linkfinder/linkfinder-report-https.html 2>/dev/null
}


wayback_gen_wordlists () {
	mkdir wordlists
	[ -s wayback/phpurls.txt ]  && sed "s/.*\///g" wayback/phpurls.txt | sed "s/\?.*//g" | sort -u | grep php > wordlists/wayback-php.txt
	[ -s wayback/aspxurls.txt ] && sed "s/.*\///g" wayback/aspxurls.txt | sed "s/\?.*//g" | sort -u | grep aspx > wordlists/wayback-aspx.txt
	[ -s wayback/jspurls.txt ]  && sed "s/.*\///g" wayback/jspurls.txt | sed "s/\?.*//g" | sort -u | grep jsp > wordlists/wayback-jsp.txt
	[ -s wayback/waybackurls.txt ] && cat wayback/waybackurls.txt | unfurl -u paths | grep -E "\/$" > wordlists/wayback-dirs.txt 

	echo -e "${blue}[+] ${green}Auto generated content discovery wordlists saved to output-domains/wordlists${reset}"
}

domain_wayback () {
	if [ "$#" -ne 1 ]; then
		echo "${red}Usage: domain_wayback <output-dir>${reset}"
		return
	fi

	cd output-domains-$1
	mkdir wayback

	if [ ! -f domains.txt ]; then 
		echo "${red}[!] $1/domains.txt does not exist!"
		cd ..
		return
	fi
	cat domains.txt | waybackurls > wayback/waybackurls.txt

	# Url parameters
	cat wayback/waybackurls.txt | sort -u | unfurl --unique keys > wayback/params.txt 
	[ -s wayback/params.txt ] 	&& echo "${blue}[+] ${green}Wordlist saved to output-domains/wayback/params.txt${reset}"
	
	# File types
	# Output check if files have been made
	cat wayback/waybackurls.txt | sort -u | grep -P "\w+\.js(\?|$)" | sort -u 	> wayback/jsurls.txt
	[ -s wayback/jsurls.txt ] 	&& echo "${blue}[+] ${green}Wordlist saved to output-domains/wayback/jsurls.txt${reset}"

	cat wayback/waybackurls.txt | sort -u | grep -P "\w+\.php(\?|$)" | sort -u 	> wayback/phpurls.txt
	[ -s wayback/phpurls.txt ] 	&& echo "${blue}[+] ${green}Wordlist saved to output-domains/wayback/phpurls.txt${reset}"

	cat wayback/waybackurls.txt | sort -u | grep -P "\w+\.aspx(\?|$)" | sort -u	> wayback/aspxurls.txt
	[ -s wayback/aspxurls.txt ]	&& echo "${blue}[+] ${green}Wordlist saved to output-domains/wayback/aspxurls.txt${reset}"

	cat wayback/waybackurls.txt | sort -u | grep -P "\w+\.jsp(\?|$)" | sort -u 	> wayback/jspurls.txt
	[ -s wayback/jspurls.txt ] 	&& echo "${blue}[+] ${green}Wordlist saved to output-domains/wayback/jspurls.txt${reset}"

	cat wayback/waybackurls.txt | sort -u | grep -P "\w+\.txt(\?|$)" | sort -u 	> wayback/txturls.txt
	[ -s wayback/txturls.txt ] 	&& echo "${blue}[+] ${green}Wordlist saved to output-domains/wayback/txturls.txt${reset}"

	wayback_gen_wordlists
	cd ..
}

domain_ss () {
	if [ "$#" -ne 1 ]; then
		echo "${red}Usage: domain_ss <alive-domains-http>${reset}"
		return
	fi
	# Aquatone screenshotting
	mkdir aquatone
	cd aquatone
	
	cat ../$1 | aquatone > /dev/null 
	cd ../
	mv aquatone* aquatone/ 2> /dev/null
}

portscan () {
	if [ "$#" -ne 1 ]; then
		echo "${red}Usage: portscan <ips-clean.txt>${reset}"
		return	
	fi

	mkdir -p portscan/nmap

	echo -e "${blue}[*] ${yellow}Doing masscan ... this could take a while${reset}"
	sudo masscan --top-ports 10000 -iL $1 --output-filename portscan/masscan-ports.json --output-format json
	jq '[.[] | {ip: .ip, port: .ports[].port}]' portscan/masscan-ports.json > portscan/masscan.json

	echo -e "${blue}[*] ${yellow}Doing nmap ... this could take a while${reset}"
	$TOOLSDIR/reconSai/nmapMasscanXML.py portscan/masscan.json portscan/nmap/ > /dev/null

	return
}

domain_http_ip_generation () {
	if [ "$#" -ne 2 ]; then
		echo "${red}Usage: domain_http_ip_generation <alive-domains.txt> <domain.com>${reset}"
		return
	fi
	# Check for virgin media redirects, mail servers, etc...
	echo -e "${blue}[*] ${yellow}Enumerating IPs, mail servers and aliases${reset}"

	# If you don't have parallel or don't want to do multithreading
	# for i in `cat $1`; do echo "http://$i" >> alive-domains-http.txt; host $i | grep -v "not found" | sed "s/has address //" | sed "s/has IPv6 address //" >> alive-hosts-tmp.txt; done

	parallel -j20 --plus echo "http://{}" :::: $1 > alive-domains-http.txt
	parallel -j30 --plus 'host "{}" | grep -v "not found" |  sed "s/has address //" | sed "s/has IPv6 address //" ' :::: $1 | uniq | sort -n > resolved-hosts.txt

	# Have a list of IP address
	echo -e "${blue}[*] ${yellow}Generating a list of IPv4 and IPv6 Addresses${reset}"
	grep -E '[0-9]+\.[0-9]+\.' resolved-hosts.txt | grep $2 | cut -d' ' -f2 | sort -u > ips.txt
	
}

depr_subfinder () {
	echo -e "${yellow}Subfinder\n${reset}"
	subfinder -d $1 -o temp/subfinder.txt
	echo -e "${yellow}PassiveHunter\n${reset}"
	passivehunter $1 false | grep $1 > temp/passivehunter.txt
	echo -e "${yellow}Amass OWASP Passive scan\n${reset}"
	amass enum -passive -src -d $1 -o temp/amass-unclean.txt

	# Cleanup
	cat temp/amass-unclean.txt | tr -d ' ' | cut -d']' -f2 > temp/amass.txt
	cat temp/amass.txt temp/passivehunter.txt temp/subfinder.txt | sort -n | uniq > domains.txt
	echo "${green}Domains written to ./output-domains-$1/domains.txt${reset}"
}

massdnssh () {
	if [ "$#" -ne 1 ];then 
		echo "${red}Usage: massdnssh <domain> ${reset}"
		return
	fi
	mkdir massdns
	
	# Hard coded paths
	echo -e "${blue}[*] ${yellow}Running massdns${reset}"
	echo -e "${blue}\t[*] ${yellow}Looking for PTR Records${reset}"
	massdns -r $TOOLSDIR/lists/resolvers domains.txt -t PTR -w massdns/ptr-records.txt 2> /dev/null
	echo -e "${blue}\t[*] ${yellow}Looking for A/AAAA Records${reset}"
	massdns -r $TOOLSDIR/lists/resolvers domains.txt -t AAAA -w massdns/aaaa-a-records.txt 2> /dev/null
	echo -e "${blue}\t[*] ${yellow}Looking for MX Records${reset}"
	massdns -r $TOOLSDIR/lists/resolvers domains.txt -t MX -w massdns/mx-records.txt 2> /dev/null
	echo -e "${blue}\t[*] ${yellow}Looking for TXT Records${reset}"
	massdns -r $TOOLSDIR/lists/resolvers domains.txt -t TXT -w massdns/txt-records.txt 2> /dev/null
	
	grep "IN TXT" massdns/txt-records.txt | grep $1 > massdns-txt-records.txt

}


gf_patterns () {
	mkdir patterns
	
	do_ting () {
		echo -e "${blue}\t[*] ${yellow}Looking for $i patterns${reset}"
		cat wayback/waybackurls.txt crawler/all.txt | gf $i > patterns/$i.txt
	}
	
	for i in `ls ~/.gf | sed "s/\.json//g"`
	do
	   do_ting $i
   	done	   

	echo -e "${blue}[*] ${green}Finished on tomnomnom's gf !${reset}"
}

shodanQuery () { 
	if [ "$#" -ne 2 ];then
		echo -e "${red}Usage: shodanQuery <ip|query|count> string${reset}"
		return
	fi
	
	RESULTS=./shodan-results.txt
	echo -e "${blue}[*] ${yellow}Running the shodan search ... ${reset}"

	# Hard coded path 
	case $1 in 
		ip)
			$TOOLSDIR/reconSai/shodanSearch.py --file "$TOOLSDIR/reconSai/apikeys.json" --ip "$2"	> $RESULTS
			;;
		query)
			$TOOLSDIR/reconSai/shodanSearch.py --file "$TOOLSDIR/reconSai/apikeys.json" --query "$2" > $RESULTS
			;;
		count)
			$TOOLSDIR/reconSai/shodanSearch.py --file "$TOOLSDIR/reconSai/apikeys.json" --count --query "$2" > $RESULTS
			;;
		*)
			echo -e "${red}Usage: shodanQuery <ip|query|count> string${reset}"
			return
			;;
	esac

	echo -e "${red}[!] ${green}Results saved to $RESULTS ${reset}"
}

crawler () {
	mkdir crawler
	echo -e "${blue}[*] ${yellow}Running crawlers ... this will take a while${reset}" 
	cat alive-domains-http.txt | gau > crawler/all.txt
	[ -s crawler/all.txt ] && echo "${blue}[+] ${green}Crawler output saved to output-domains/crawler/all.txt${reset}"
	
	grep -i -e "url=" -e "redirect=" -e "url" -e "next=" -e "dest=" -e "destination" -e "go=" -e "redirect_uri" -e "continue=" -e "return_path=" -e "externalLink=" crawler/all.txt > crawler/open-redirects.txt
	[ -s crawler/open-redirects.txt ] && echo "${blue}[+] ${green}Crawler output saved to output-domains/crawler/open-redirects.txt${reset}"
	
	cat crawler/all.txt | unfurl format %q | sed "s/\&/\n/g" | sort -u > crawler/params.txt
	[ -s crawler/params.txt ] && echo "${blue}[+] ${green}Crawler output saved to output-domains/crawler/params.txt${reset}"
	
	grep -iE -e api -e oath -e o.auth -e oauth -e '\/v[0-9]\/' -e 'graphql' -e 'rest' -e 'wp-' crawler/all.txt > crawler/apis.txt
	[ -s crawler/apis.txt ] && echo "${blue}[+] ${green}Crawler output saved to output-domains/crawler/apis.txt${reset}"

	grep -iE -e 'config' -e '\.xml' -e '\.json' -e '\.yml' crawler/all.txt > crawler/configs.txt 
	[ -s crawler/configs.txt ] && echo "${blue}[+] ${green}Crawler output saved to output-domains/crawler/configs.txt${reset}"

}

monitor_mode () {
	if [ "$#" -ne 2 ];then
		echo "${red}Usage: monitor_mode <domain> <domains-wildcards.txt>${reset}"
		return
	fi
	WHOLETING=$(readlink -f $2)
	PATHTING=$(dirname $WHOLETING)
	TEMPDIR=$(mktemp -d)
	main $1 "f" $TEMPDIR
	CHECK=$(git diff $WHOLETING domains-wildcards.txt | grep -E "^(\-|\+)[a-zA-Z0-9]")
	if [ "$CHECK" ]; then
		echo -n "${yellow}[*]${reset} " >> $PATHTING/domains-changes.txt
		date >> $PATHTING/domains-changes.txt
		echo -e "$CHECK\n" >> $PATHTING/domains-changes.txt
		mv domains-wildcards.txt $WHOLETING
	fi
	cd ..
	rm -rf "output-domains-$1"
}

main () {
	if [ "$#" -lt 2 ]; then
		echo "${red}Usage: main <domain> (check alive)<t|f> [dir]${reset}"
		return
	fi
	if [ "$2" != "t" ] && [ "$2" != "f" ]; then
		echo "${red}Usage: main <domain> (check alive)<t|f> [dir]${reset}"
		return
	fi

	if [ $3 ] && [ -d $3 ]; then
		cd $3
	else
		[ ! -d ouput-domains-$1 ] && mkdir output-domains-$1
		cd output-domains-$1
	fi
		
	[ ! -d temp ] && mkdir temp
	echo -e "${blue}[*] ${yellow}Running sublist3r ... this will take ages${reset}"
	sublist3r -d $1 -o temp/sublister-unclean.txt > /dev/null 
	sed "s/<BR>/\n/g" temp/sublister-unclean.txt > temp/sublister.txt

	echo -e "${blue}[*] ${yellow}Running amass... this will take ages${reset}"
	amass enum -passive -d $1 -o temp/amass.txt > /dev/null 2> /dev/null

	echo -e "${blue}[*] ${yellow}Running subfinder ... ${reset}"
	subfinder -d $1 -o temp/subfinder.txt > /dev/null 2> /dev/null

	echo -e "${blue}[*] ${yellow}Running crt.sh${resets}"
	curl -s "https://crt.sh/?q=%.$1" | grep "$1" | grep '<TD>' | sed "s/^.*<TD>//g; s/<\/TD>//g; s/<BR>/\n/g" | sort -u > temp/crt.txt

	echo -e "${blue}[*] ${yellow}Running assetfinder${resets}"
	assetfinder $1 > temp/assetfinder.txt

	cat temp/sublister.txt temp/crt.txt temp/subfinder.txt temp/assetfinder.txt temp/amass.txt | sort -u > domains-wildcards.txt
	sed "s/\*\.//g" domains-wildcards.txt > domains.txt

	if [ "$2" == "t" ]; then
		# Check alive subdomains
		domain_alive_check "domains.txt"
		domain_http_ip_generation "alive-domains.txt" $1
		echo -e "${blue}[+] ${green}\nInteresting info\n${reset}"
		cat resolved-hosts.txt | grep -Ev -e ":" -e '[0-9]+\.[0-9]+\.'
	fi

	return
}

# Grep for Hard coded and edit those 
# echo -e "Usage:"
# echo -e "$ . /path/to/library\n"
# echo -e "Now you can run any of the commands"
# echo 

