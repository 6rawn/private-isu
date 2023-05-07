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

download_alp
download_ab
download_mysql_client

if [[ "$UNAME" == *Linux* ]];
then
    download_dstat
fi
