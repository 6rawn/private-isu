#!/bin/bash

UNAME=$(uname -a)

ALP_URL="https://github.com/tkuchiki/alp/releases/download/v1.0.12/alp_linux_amd64.zip"
DOWNLOAD_AB="sudo apt-get install -y apache2-utils"
DOWNLOAD_MYSQL_CLIENT="sudo apt-get install -y mysql-client"
DOWNLOAD_DSTAT="sudo apt-get install -y dstat"

if [[ "$UNAME" == *Darwin* ]];
then
	DOWNLOAD_AB="brew install homebrew/apache/ab"
    DOWNLOAD_MYSQL_CLIENT="brew install mysql-client"

    if [[ "$UNAME" == *"x86_64"* ]];
    then
    	ALP_URL="https://github.com/tkuchiki/alp/releases/download/v1.0.12/alp_darwin_amd64.zip"
    elif [[ "$UNAME" == *"arm64"* ]];
    then
    	ALP_URL="https://github.com/tkuchiki/alp/releases/download/v1.0.12/alp_darwin_arm64.zip"
    fi
fi


download_alp() {
    if [[ ! -f alp ]];
    then
        curl -L -o alp.zip ${ALP_URL};unzip alp.zip
    fi
}

download_ab() {
    if ! which ab >& /dev/null;
    then
        eval "${DOWNLOAD_AB}"
    fi
}

download_mysql_client() {
    if ! which mysqldumpslow >& /dev/null;
    then
        eval "${DOWNLOAD_MYSQL_CLIENT}"
    fi
}

download_dstat() {
    if ! which dstat >& /dev/null;
    then
        eval "${DOWNLOAD_DSTAT}"
    fi
}

download_k6() {
    if [[ "$UNAME" == *Linux* ]];
    then
        sudo gpg -k
        sudo gpg --no-default-keyring --keyring /usr/share/keyrings/k6-archive-keyring.gpg --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys C5AD17C747E3415A3642D57D77C6C491D6AC1D69
        echo "deb [signed-by=/usr/share/keyrings/k6-archive-keyring.gpg] https://dl.k6.io/deb stable main" | sudo tee /etc/apt/sources.list.d/k6.list
        sudo apt-get update
        sudo apt-get install -y k6
    fi

    if [[ "$UNAME" == *Darwin* ]];
    then
        brew instsall k6
    fi
}

download_alp
download_ab
download_mysql_client
download_k6

if [[ "$UNAME" == *Linux* ]];
then
    download_dstat
fi
