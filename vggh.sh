#!/bin/bash

#source ~/.bashacker

#color

red='\e[1;31m%s\e[0m\n'
green='\e[1;32m%s\e[0m\n'
yellow='\e[1;33m%s\e[0m\n'
blue='\e[1;34m%s\e[0m\n'
magenta='\e[1;35m%s\e[0m\n'
cyan='\e[1;36m%s\e[0m\n'

##################################################################
clear

: '
echo "For amass intel normal scan enter 1A"
echo "For amass asn scan enter 2A"
echo "For amass intel org normal scan enter 3A"
echo "For amass intel combined scan enter 4A"
echo "For amass enum passive scan enter 5A"
echo "For amass enum active scan enter 1A"
'

#dir setup
read -p  "Enter the company name: " cm
mkdir /app/$cm
cd /app/$cm
read -p "Enter the root Domain: " dm
clear

#usage
#echo "amass enum -passive -d doamin -src
#amass intel -org 'Example Ltd
#amass intel -active -asn 222222 -ip
#amass intel -d owasp.org -whois
#amass intel -active -cidr 1.1.1.1
#amass intel -asn 11111 -whois -d doamin.com
#amass enum -d example.com -active -cidr 1.2.3.4/24,4.3.2.1/24 -asn 12345
#amass enum -brute -active -d domain.com -o amass-output.txt"

#read -p "Enter the amass cmd " AO
clear
#################################################################

# Amass
printf "$green"   "...amass started..."
printf "$cyan"    "...Domain = $dm..."
printf ""
sleep 1

/app/binaries/amass enum -passive -norecursive -nolocaldb -noalts -d $dm -o /app/$cm/amass.txt
#cat /app/$cm/amass.txt >> /app/$cm/all.txt

/app/binaries/amass enum -brute -active -d cm -o /app/$cm/amass-enum.txt
echo -e "\e[36mAmaas count: \e[32m$(cat /app/$cm/amass.txt | tr '[:upper:]' '[:lower:]'| /app/binaries/anew | wc -l)\e[0m"
python3 /app/p.py --type hi --path /app/$cm/amass.txt --caption normal-amass RESULTS
python3 /app/p.py --type hi --path /app/$cm/amass-enum.txt --caption amass-enum RESULTS

#################################################################

# WayBackEngine  ENUMERATION
printf "$green"   "...WayBackEngine  ENUMERATION started..."
printf "$cyan"    "...Domain = $dm..."
printf ""
sleep 1

curl -sk "http://web.archive.org/cdx/search/cdx?url=*."$dm"&output=txt&fl=original&collapse=urlkey&page=" | awk -F / '{gsub(/:.*/, "", $3); print $3}' | /app/binaries/anew | sort -u >> /app/$cm/wayback.txt
#cat /app/$cm/wayback.txt >> /app/$cm/all.txt
echo -e "\e[36mWayBackEngine count: \e[32m$(cat /app/$cm/wayback.txt.txt | tr '[:upper:]' '[:lower:]'| /app/binaries/anew | wc -l)\e[0m"
python3 /app/p.py --type hi --path /app/$cm/wayback.txt --caption wayback.txt RESULTS

#################################################################

# BufferOver ENUMERATION
printf "$green"   "...BufferOver ENUMERATION started..."
printf "$cyan"    "...Domain = $dm..."
printf ""
sleep 1

curl -s "https://dns.bufferover.run/dns?q=."$dm"" | grep $dm | awk -F, '{gsub("\"", "", $2); print $2}' | /app/binaries/anew >> /app/$cm/bufferover.txt
#cat /app/$cm/bufferover.txt >> /app/$cm/all.txt
echo -e "\e[36mBufferOver Count: \e[32m$(cat /app/$cm/bufferover.txt | tr '[:upper:]' '[:lower:]'| /app/binaries/anew | wc -l)\e[0m"
python3 /app/p.py --type hi --path /app/$cm/bufferover.txt --caption bufferover.txt RESULTS

#################################################################

# CERTIFICATE ENUMERATION
printf "$green"   "...CERTIFICATE ENUMERATION started..."
printf "$cyan"    "...Domain = $dm..."
printf ""
sleep 1

registrant=$(whois $dm | grep "Registrant Organization" | cut -d ":" -f2 | xargs| sed 's/,/%2C/g' | sed 's/ /+/g'| egrep -v '(*Whois*|*whois*|*WHOIS*|*domains*|*DOMAINS*|*Domains*|*domain*|*DOMAIN*|*Domain*|*proxy*|*Proxy*|*PROXY*|*PRIVACY*|*privacy*|*Privacy*|*REDACTED*|*redacted*|*Redacted*|*DNStination*|*WhoisGuard*|*Protected*|*protected*|*PROTECTED*)')
if [ -z "$registrant" ]
then
        curl -s "https://crt.sh/?q="$dm"&output=json" | jq -r ".[].name_value" | sed 's/*.//g' | /app/binaries/anew >> /app/$cm/whois.txt
else
	curl -sk "https://crt.sh/?O=$registrant&output=json" | tr ',' '\n' | awk -F'"' '/common_name/ {gsub(/\*\./, "", $4); gsub(/\\n/,"\n",$4);print $4}' |sort -u |/app/binaries/anew >> /app/$cm/whois.txt
        curl -s "https://crt.sh/?q=$registrant" | grep -P -i '<TD>([a-zA-Z]+(\.[a-zA-Z]+)+)</TD>' | sed -e 's/^[ \t]*//' | cut -d ">" -f2 | cut -d "<" -f1 | /app/binaries/anew >> /app/$cm/whois.txt
        curl -s "https://crt.sh/?q=$dm&output=json" | jq -r ".[].name_value" | sed 's/*.//g' | /app/binaries/anew >> /app/$cm/whois.txt
fi

registrant2=$(whois $dm | grep "Registrant Organisation" | cut -d ":" -f2 | xargs| sed 's/,/%2C/g' | sed 's/ /+/g'| egrep -v '(*Whois*|*whois*|*WHOIS*|*domains*|*DOMAINS*|*Domains*|*domain*|*DOMAIN*|*Domain*|*proxy*|*Proxy*|*PROXY*|*PRIVACY*|*privacy*|*Privacy*|*REDACTED*|*redacted*|*Redacted*|*DNStination*|*WhoisGuard*|*Protected*|*protected*|*PROTECTED*)')
if [ -z "$registrant2" ]
then
        curl -s "https://crt.sh/?q="$dm"&output=json" | jq -r ".[].name_value" | sed 's/*.//g' | /app/binaries/anew >> /app/$cm/whois.txt
else
        curl -s "https://crt.sh/?q="$registrant2"" | grep -a -P -i '<TD>([a-zA-Z]+(\.[a-zA-Z]+)+)</TD>' | sed -e 's/^[ \t]*//' | cut -d ">" -f2 | cut -d "<" -f1 | /app/binaries/anew >> /app/$cm/whois.txt
        curl -s "https://crt.sh/?q="$dm"&output=json" | jq -r ".[].name_value" | sed 's/*.//g' | /app/binaries/anew >> /app/$cm/whois.txt
fi
#cat /app/$cm/whois.txt|/app/binaries/anew|grep -v " "|grep -v "@" | grep "\." >> /app/$cm/all.txt
echo -e "\e[36mCertificate search count: \e[32m$(cat /app/$cm/whois.txt | tr '[:upper:]' '[:lower:]'| /app/binaries/anew | grep -v " "|grep -v "@" | grep "\." | wc -l)\e[0m"
python3 /app/p.py --type hi --path /app/$cm/whois.txt --caption whois.txt RESULTS

#################################################################

# DNSCAN ENUMERATION
printf "$green"   "...DNSCAN ENUMERATION started..."
printf "$cyan"    "...Domain = $dm..."
printf ""
sleep 1

python3 /app/tools/frogy-main/dnscan/dnscan.py -d %%.$dm -w /app/tools/frogy-main/wordlist/subdomains-top1million-5000.txt -D -o /app/$cm/dnstemp.txtls &> /dev/null
cat /app/$cm/dnstemp.txtls | grep $dm | egrep -iv ".(DMARC|spf|=|[*])" | cut -d " " -f1 | /app/binaries/anew | sort -u | grep -v " "|grep -v "@" | grep "\." >>  /app/$cm/dnscan.txt
#rm /app/$cm/dnstemp.txt
echo -e "\e[36mDnscan: \e[32m$(cat /app/$cm/dnscan.txt | tr '[:upper:]' '[:lower:]'| /app/binaries/anew | grep -v " "|grep -v "@" | grep "\." | wc -l)\e[0m"
python3 /app/p.py --type hi --path /app/$cm/dnscan.txt --caption dnscan.txt RESULTS

#################################################################

# assetfinder
printf "$green"   "...assetfinder started..."
printf "$cyan"    "...Domain = $dm..."
printf ""
sleep 1

/app/binaries/assetfinder --subs-only $dm >> /app/$cm/assetfinder.txt
python3 /app/p.py --type hi --path /app/$cm/assetfinder.txt --caption assetfinder.txt RESULTS

##################################################################

#finddomain
sleep 1
printf "$green"   "...findomain started..."
printf "$cyan"    "...Domain = $dm..."
echo ""

/app/binaries/findomain-linux -t $dm >> /app/$cm/findomain.txt
#cat /app/$cm/findomain.txt|/app/binaries/anew|grep -v " "|grep -v "@" | grep "\." >> /app/$cm/all.txt
echo -e "\e[36mFindomain count: \e[32m$(cat /app/$cm/findomain.txt | tr '[:upper:]' '[:lower:]'| /app/binaries/anew |grep -v " "|grep -v "@" | grep "\."| wc -l)\e[0m"
python3 /app/p.py --type hi --path /app/$cm/findomain.txt --caption findomain.txt RESULTS

##################################################################

#sublist3r
sleep 1
printf "$green"   "...sublist3r started..."
printf "$cyan"    "...Domain = $dm..."
echo ""

python /app/tools/Sublist3r/sublist3r.py -d $dm -no /app/$cm/sublister.txtls
if [ -f "sublister.txtls" ]; then
        cat sublister_output.txt|/app/binaries/anew|grep -v " "|grep -v "@" | grep "\." >> /app/$cm/sublister.txt
        #rm sublister_output.txt
	#cat /app/$cm/sublister.txt|/app/binaries/anew|grep -v " "|grep -v "@" | grep "\." >> /app/$cm/all.txt
	echo -e "\e[36mSublister count: \e[32m$(cat /app/$cm/sublister.txt | tr '[:upper:]' '[:lower:]'| /app/binaries/anew | wc -l)\e[0m"
else
        echo -e "\e[36mSublister count: \e[32m0\e[0m"
fi
python3 /app/p.py --type hi --path /app/$cm/sublister.txtls --caption sublister.txtls RESULTS
python3 /app/p.py --type hi --path /app/$cm/sublister.txt --caption sublister.txt RESULTS

##################################################################

#subfinder
echo ""
sleep 1
printf "$green"   "...subfinder started..."
printf "$cyan"    "...Domain = $dm..."
echo ""

/app/binaries/subfinder -d $dm -o /app/$cm/subfinder.txt
echo -e "\e[36mSubfinder count: \e[32m$(cat /app/$cm/subfinder2.txt | tr '[:upper:]' '[:lower:]'| /app/binaries/anew | grep -v " "|grep -v "@" | grep "\."  | wc -l)\e[0m"
#cat /app/$cm/subfinder2.txt | grep "/" | cut -d "/" -f3 | grep -v " "|grep -v "@" | grep "\." >> /app/$cm/all.txt
#cat /app/$cm/subfinder2.txt | grep -v "/" | grep -v " "|grep -v "@" | grep "\."  >> /app/$cm/all.txt
python3 /app/p.py --type hi --path /app/$cm/subfinder.txt --caption subfinder.txt RESULTS

##################################################################

#git-search
sleep 1
echo ""
printf "$green"   "...github recon started..."
printf "$cyan"    "...Domain = $dm..."
echo ""

python /app/tools/github-search/github-subdomains.py -t <YOUR-TOKEN> -d $dm | tee /app/$cm/subfinder.txt
python3 /app/p.py --type hi --path /app/$cm/subfinder.txt --caption subfinder.txt RESULTS

##################################################################

#subbrute 
sleep 1
echo ""
printf "$green"   "...subbrute started..."
printf "$cyan"    "...Domain = $dm..."
echo ""

python3 /app/tools/subbrute/subbrute.py $dm -o /app/$cm/subrute.txt
python3 /app/p.py --type hi --path /app/$cm/subrute.txt --caption subrute.txt RESULTS

##################################################################
#################################################################
#/app/binaries/anew
printf "$green"   ".../app/binaries/anew..."
printf "$cyan"    "...Domain = $dm..."
printf ""
sleep 1

# short all domains into one
echo ""
printf "$yellow"  "removing duplicates"
cat /app/$cm/*.txt | grep "/" | cut -d "/" -f3 | grep -v " "|grep -v "@" | grep "\." >> /app/$cm/old_output.txt
cat /app/$cm/*.txt | grep -v "/" | grep -v " "|grep -v "@" | grep "\."  >> /app/$cm/old_output.txt
cat /app/$cm/old_output.txt | tr '[:upper:]' '[:lower:]'| /app/binaries/anew | grep -v "*." | grep -v " "|grep -v "@" | grep "\." >> /app/$cm/$cm.master
python3 /app/p.py --type hi --path /app/$cm/old_output.txt --caption old_output.txt RESULTS

#################################################################

# GATHERING ROOT DOMAINS
printf "$green"   "...GATHERING ROOT DOMAINS started..."
printf "$cyan"    "...Domain = $dm..."
printf ""
sleep 1

python3 /app/tools/frogy-main/rootdomain.py | cut -d " " -f7 | tr '[:upper:]' '[:lower:]' | /app/binaries/anew | sed '/^$/d' | grep -v " "|grep -v "@" | grep "\." >> /app/$cm/rootdomain.txt
cat /app/$cm/rootdomain.txt | tr '[:upper:]' '[:lower:]'| /app/binaries/anew | grep -v "*." | grep -v " "|grep -v "@" | grep "\." >> /app/$cm/$cm.master
echo -e "\e[36mRootDomains Count: \e[32m$(cat /app/$cm/rootdomain.txt | tr '[:upper:]' '[:lower:]'| /app/binaries/anew | wc -l)\e[0m"
python3 /app/p.py --type hi --path /app/$cm/rootdomain.txt --caption rootdomain.txt RESULTS

##################################################################

#SUBDOMAIN RESOLVER
printf "$green"   "dnsgen"

while read d || [[ -n $d ]]; do
  ip=$(dig +short $d|grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b"|head -1)
  if [ -n "$ip" ]; then
    echo "$d,$ip" >>/app/$cm/resolved.txtls
  else
    echo "$d,Can't Resolve" >>/app/$cm/resolved.txtls
  fi
done </app/$cm/$cm.master
sort /app/$cm/resolved.txtls | uniq > /app/$cm/resolved.txt
cat /app/$cm/resolved.txt | tr '[:upper:]' '[:lower:]'| /app/binaries/anew | grep -v "*." | grep -v " "|grep -v "@" | grep "\." >> /app/$cm/$cm.master
#mv /app/$cm/resolved.new /app/$cm/resolved.txt
python3 /app/p.py --type hi --path /app/$cm/resolved.txt --caption resolved.txt RESULTS

##################################################################

#dnsgen
printf "$green"   "dnsgen"

cat /app/$cm/old_output.txt | dnsgen - > /app/$cm/dnsgen-https.txt
cat /app/$cm/dnsgen-https.txt | tr '[:upper:]' '[:lower:]'| /app/binaries/anew | grep -v "*." | grep -v " "|grep -v "@" | grep "\." >> /app/$cm/$cm.master
python3 /app/p.py --type hi --path /app/$cm/dnsgen-https.txt --caption dnsgen-https.txt RESULTS

#################################################################

# aquatone

printf "$green"   "taking screenshorts in live https domains"

cat /app/$cm/$cm.master | /app/binaries/aquatone -out /app/$cm/aquatone/
#python3 /app/p.py --type hi --path /app/$cm/bufferover.txt --caption bufferover.txt RESULTS

#################################################################

# eyewithness
printf "$green"   "Taking screenshorts"

mkdir /app/$cm/screenshort
eyewitness -f /app/$cm/$cm.master -d /app/$cm/screenshort/
#python3 /app/p.py --type hi --path /app/$cm/bufferover.txt --caption bufferover.txt RESULTS

##################################################################

# dir search
printf "$green"   "dir search"
printf "$yellow"  "if you dont want to run this press 'ctrl + c to stop"
mkdir /app/$cm/dirsearch
while read -r data ; do
echo " Domain : $data"
python3 /app/tools/dirsearch-master/dirsearch.py -u $data -e php,asp,aspx,net,js,cs,php2,php3,php4,php5,php6,php7,jsp,java,python,yaml,yml,config,conf,htaccess,htpasswd,shtml | tee /app/$cm/dirsearch/$data.txt
done < /app/$cm/$cm.master
cat /app/$cm/dirsearch/*.txt >> /app/$cm/dirsearch.txt
python3 /app/p.py --type hi --path /app/$cm/dirsearch.txt --caption dirsearch.txt RESULTS

##################################################################

# Finding params

printf "$green"   "Findigs parram"
mkdir /app/$cm/params

while read -r line ; do
 echo " Domain : $line"
python3 /app/tools/P4R4M-HUNT3R-master/P4R4M-HUNT3R/param-hunter.py --domain $line > /app/$cm/params/$line.txt
done < /app/$cm/$cm.master
cat /app/$cm/params/*.txt > /app/$cm/params.txt
python3 /app/p.py --type hi --path /app/$cm/params.txt --caption params.txt RESULTS

##################################################################

# Finding vulnerables
printf "$green"   "Findigs xss"
/app/binaries/gf xss /app/$cm/params.txt | tee /app/$cm/xss.txt

/app/binaries/gf redirect /app/$cm/params.txt | tee /app/$cm/redirects.txt
python3 /app/p.py --type hi --path /app/$cm/xss.txt --caption xss.txt RESULTS

##################################################################

#FINDING LOGIN PORTALS

portlst=`/app/binaries/naabu -l /app/$cm/$cm.master -pf ports -silent | cut -d ":" -f2 | /app/binaries/anew | tr "\n" "," | sed 's/.$//'` &> /dev/null

/app/binaries/httpx -silent -l /app/$cm/$cm.master -p $portlst -fr -include-chain -store-chain -sc -tech-detect -server -title -cdn -cname -probe -srd /app/$cm/aw_http_responses/ -o /app/$cm/temp_live.txt &> /dev/null

cat /app/$cm/temp_live.txt | grep SUCCESS | cut -d "[" -f1 >> /app/$cm/livesites.txt
python3 /app/p.py --type hi --path /app/$cm/livesites.txt --caption livesites.txt RESULTS

cat /app/$cm/temp_live.txt | grep SUCCESS >> /app/$cm/technology.txt
python3 /app/p.py --type hi --path /app/$cm/technology.txt --caption technology.txt RESULTS

#rm -f output/$cdir/temp_live.txtls

while read lf; do
        loginfound=`curl -s -L $lf | grep 'type="password"'`
        if [ -z "$loginfound" ]
                then
                :
        else
                echo "$lf" >> /app/$cm/loginfound.txtls
        fi

done </app/$cm/livesites.txtls
python3 /app/p.py --type hi --path /app/$cm/loginfound.txtls --caption loginfound.txtls RESULTS


echo -e "\e[93mTotal live websites (on all available ports) found: \e[32m$(cat /app/$cm/livesites.txtls | tr '[:upper:]' '[:lower:]' | anew | wc -l)\e[0m"

if [[ -f "output/$cdir/loginfound.txtls" ]]
	then
		echo -e "\e[93mTotal login portals found: \e[32m$(cat /app/$cm/loginfound.txtls | tr '[:upper:]' '[:lower:]' | anew| wc -l)\e[0m"
	else
		echo -e "\e[93mTotal login portals found: \e[32m0\e[0m"
fi

echo -e "\e[36mFinal output has been generated in the output/$cdir/ folder: \e[32moutput.csv\e[0m"

cat /app/$cm/resolved.txt | cut -d ',' -f1 >> temp1.txt
cat /app/$cm/resolved.txt | cut -d ',' -f2 >> temp2.txt
#python3 /app/p.py --type hi --path /app/$cm/temp1.txt --caption bufferover.txt RESULTS
#python3 /app/p.py --type hi --path /app/$cm/bufferover.txt --caption bufferover.txt RESULTS

if [ -f /app/$cm/loginfound.txt ]; then
	paste -d ','  /app/$cm/rootdomain.txt temp1.txt temp2.txt /app/$cm/livesites.txt /app/$cm/loginfound.txt | sed '1 i \Root Domain,Subdomain,IP Address,Live Website,Login Portals' > /app/$cm/output.csv

else
	paste -d ','  /app/$cm/rootdomain.txt temp1.txt temp2.txt /app/$cm/livesites.txt | sed '1 i \Root Domain,Subdomain,IP Address,Live Website' > /app/$cm/output.csv
fi
#rm temp1.txt temp2.txt
python3 /app/p.py --type hi --path /app/$cm/output.csv --caption output.csv RESULTS

##################################################################

#RELATIONSHIP
printf "$green"   "...RELATIONSHIP started..."
printf "$cyan"    "...Domain = $dm..."
printf ""
sleep 1

echo $cm | python3 /app/tools/getrelationship.py >> /app/$cm/relationship.txt
cat /app/$cm/SubDomainizer.txt | tr '[:upper:]' '[:lower:]'| /app/binaries/anew | grep -v "*." | grep -v " "|grep -v "@" | grep "\." >> /app/$cm/$cm.master
python3 /app/p.py --type hi --path /app/$cm/relationship.txt --caption relationship.txt RESULTS

##################################################################

#SubDomainizer
printf "$green"   "...SubDomainizer started..."
printf "$cyan"    "...Domain = $dm..."
printf ""
sleep 1

python3 /app/tools/SubDomainizer.py -d $cm -o /app/$cm/SubDomainizer.txt
cat /app/$cm/SubDomainizer.txt | tr '[:upper:]' '[:lower:]'| /app/binaries/anew | grep -v "*." | grep -v " "|grep -v "@" | grep "\." >> /app/$cm/$cm.master
python3 /app/p.py --type hi --path /app/$cm/SubDomainizer.txt --caption SubDomainizer.txt RESULTS

##################################################################

#favfreak
printf "$green"   "...hakrawler started..."
printf "$cyan"    "...Domain = $dm..."
printf ""
sleep 1

cat /app/$cm/live.txt  | python3 favfreak.py -o output /app/$cm/favfreak.txt
cat /app/$cm/favfreak.txt | tr '[:upper:]' '[:lower:]'| /app/binaries/anew | grep -v "*." | grep -v " "|grep -v "@" | grep "\." >> /app/$cm/$cm.master
python3 /app/p.py --type hi --path /app/$cm/favfreak.txt --caption favfreak.txt RESULTS

##################################################################

#GO-SPIDER
printf "$green"   "...GO-SPIDER started..."
printf "$cyan"    "...Domain = $dm..."
printf ""
sleep 1

mkdir /app/$cm/paths
/app/binaries/gospider -s "https://$cm/" -c 10 -d 1 --other-source --include-subs --js --sitemap -a -r -o output /app/$cm/paths/gospider.txt  
python3 /app/p.py --type hi --path /app/$cm/paths/gospider.txt  --caption gospider.txt  RESULTS

##################################################################

#hakrawler
printf "$green"   "...hakrawler started..."
printf "$cyan"    "...Domain = $dm..."
printf ""
sleep 1

echo $cm | /app/binaries/haktrails subdomains | /app/binaries/httpx | /app/binaries/hakrawler -depth 10 >> /app/$cm/paths/hakrawler.txt
python3 /app/p.py --type hi --path /app/$cm/paths/hakrawler.txt --caption hakrawler.txt RESULTS

##################################################################

# finding live domains
printf "$green"   "Scanning for live domain"

cat /app/$cm/$cm.master | /app/binaries/httprobe -c 50 -t 3000 -p 443 | tee -a /app/$cm/live.txt
cat /app/$cm/live.txt | wc -l

cat /app/$cm/$cm.master | /app/binaries/httprobe -p http:81 -p http:3000 -p https:3000 -p http:3001 -p https:3001 -p http:8000 -p http:8080 -p https:8443 -c 50 | tee -a /app/$cm/otherport-domains.txt
python3 /app/p.py --type hi --path /app/$cm/live.txt --caption live.txt RESULTS
python3 /app/p.py --type hi --path /app/$cm/otherport-domains.txt --caption otherport-domains.txt RESULTS
python3 /app/p.py --type hi --path /app/$cm/$cm.master --caption $cm.master RESULTS

#################################################################

# grep https domains
printf "$green"   "grep only https"

cat /app/$cm/live.txt | grep "https" | cut -d"/" -f3 > /app/$cm/live-https.txt
cat /app/$cm/live-https.txt | wc -l
python3 /app/p.py --type hi --path /app/$cm/live-https.txt --caption live-https.txt RESULTS

#################################################################3
