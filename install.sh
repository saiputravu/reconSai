#!/bin/bash

TOOLSDIR=~/reconTools/

sudo apt update 
sudo apt install -y git \
	make \
	cmake \
	binutils \
	net-tools \
	python3 python3-pip \
	parallel

mkdir -p $TOOLSDIR
chown $TOOLSDIR `id -u -n`:`id -g -n`

# Move all the directory to the $TOOLSDIR
if [ ! -d $TOOLSDIR ]; then
    echo "[!] Directory for tools ($TOOLSDIR) is not accessible or created."
    echo "Exiting ..."
fi

cd ..
mv reconSai $TOOLSDIR/reconSai
cd $TOOLSDIR
sudo ln -s `pwd`/reconSai/reconSai /usr/local/bin/reconSai

# Install reconSai python requirements
cd reconSai
python3 -m pip install -r requirements.txt

# Install MassDNS
cd $TOOLSDIR
git clone https://github.com/blechschmidt/massdns.git
cd massdns
make
cp -r lists $TOOLSDIR
sudo ln -s `pwd`/bin/massdns /usr/local/bin/massdns

# Install masscan
cd $TOOLSDIR
git clone https://github.com/robertdavidgraham/masscan
cd massdns
make
sudo ln -s `pwd`/bin/masscan /usr/local/bin/masscan

# Install Chromium Browser
sudo apt install chromium-browser -y

# Install Jq (Json parser)
sudo apt install jq -y

# Install linkfinder.py
cd $TOOLSDIR
git clone https://github.com/GerbenJavado/LinkFinder.git
cd LinkFinder
python3 -m pip install -r requirements.txt
echo -e '#!/bin/bash\npython3 '$TOOLSDIR'/LinkFinder/linkfinder.py $@' | sudo tee /usr/local/bin/linkfinder > /dev/null
sudo chmod +x /usr/local/bin/linkfinder

# Install go
cd $TOOLSDIR
wget https://golang.org/dl/go1.16.6.linux-amd64.tar.gz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.16.6.linux-amd64.tar.gz
rm go1.16.6.linux-amd64.tar.gz
export GOPATH=~/go/
export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin
export GO111MODULE=off # Enables git cloning to $GOPATH/src/
echo 'export GOPATH=~/go/' >> ~/.bashrc
echo 'export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin' >> ~/.bashrc
echo 'export GO111MODULE=off' >> ~/.bashrc

# Install amass
GO111MODULE=on go install -v github.com/OWASP/Amass/v3/...@master
# cd $TOOLSDIR
# git clone https://github.com/OWASP/Amass.git

# Install nmap
sudo apt install nmap -y

# Install aquatone
cd  $TOOLSDIR
wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip
unzip aquatone_linux_amd64_1.7.0.zip
rm *.md *.txt *.zip 
chmod +x aquatone
sudo ln -s `pwd`/aquatone /usr/local/bin/aquatone

# Install subfinder
GO111MODULE=on go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Install sublist3r
cd $TOOLSDIR
git clone https://github.com/aboul3la/Sublist3r.git
cd Sublist3r
python3 -m pip install -r requirements.txt
sudo python3 setup.py install

# Install passivehunter.py
cd $TOOLSDIR
git clone https://github.com/devanshbatham/Passivehunter
cd Passivehunter
python3 -m pip install -r requirements.txt
echo -e '#!/bin/bash\npython3 '$TOOLSDIR'/Passivehunter/passivehunter.py $@' | sudo tee /usr/local/bin/passivehunter > /dev/null
sudo chmod +x /usr/local/bin/passivehunter
cd $TOOLSDIR

# Install gf (tomnomnom)
go install github.com/tomnomnom/gf@latest
echo 'source $GOPATH/src/github.com/tomnomnom/gf/gf-completion.bash' >> ~/.bashrc
cp -r $GOPATH/src/github.com/tomnomnom/gf/examples ~/.gf

# Install waybackurls
go install github.com/tomnomnom/waybackurls@latest

# Install assetfinder
GO111MODULE=on go install github.com/tomnomnom/assetfinder@latest

# Install ffuf
GO111MODULE=on go install github.com/ffuf/ffuf@latest

# Install unfurl
GO111MODULE=on go install github.com/tomnomnom/unfurl@latest

# Install gau
GO111MODULE=on go install github.com/lc/gau@latest

# Install httprobe
GO111MODULE=on go install github.com/tomnomnom/httprobe@latest

echo "Finished installing ... "
echo "[!] Restart your terminal for changes to take effect / source your rc file"
echo 

