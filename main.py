#!/usr/bin/python3

import io
import os
import re
import sys
import time
import wget
import codecs
import asyncio
import pathlib
import requests
from os import walk
from zipfile import ZipFile
from time import gmtime, strftime
from pathlib import Path
from pysecuritytrails import SecurityTrails, SecurityTrailsError

api_st = os.getenv("SECURITYTRAILS_API")
st = SecurityTrails(api_st)

################################################################################
# Helper Functions
################################################################################


def generate_output_folder() -> None:
    if not os.path.isdir("WhatsApp"):
        os.mkdir("WhatsApp")


################################################################################
# Clean Files
################################################################################


def cleanZip() -> None:
    mypath = pathlib.Path(__file__).parent.absolute()
    f = []
    for (dirpath, dirnames, filenames) in walk(mypath):
        f.extend(filenames)
        break

    for item in f:
        if item.endswith(".zip"):
            os.remove(os.path.join(mypath, item))


################################################################################
# Save File RSC Mikrotik
################################################################################


def saveFileRSC(base_list):
    listEnd = []
    listEnd.append("# ============================================================" + "\n")
    listEnd.append("#"+ "\n")
    listEnd.append("# whatsapp_cidr_ipv4"+ "\n")
    listEnd.append("#"+ "\n")
    listEnd.append("# ipv4 mikrotik address-list"+ "\n")
    listEnd.append("#"+ "\n")
    listEnd.append("# List of the WhatsApp server IP addresses and ranges."+ "\n")
    listEnd.append("#"+ "\n")
    listEnd.append("# Maintainer      : Meta"+ "\n")
    listEnd.append("# Maintainer URL  : https://about.meta.com/"+ "\n")
    listEnd.append("# List source URL : https://developers.facebook.com/docs/whatsapp/guides/network-requirements/"+ "\n")
    listEnd.append("#"+ "\n")
    listEnd.append("# Category        : servers"+ "\n")
    listEnd.append("# Version         : 1"+ "\n")
    listEnd.append("#"+ "\n")
    listEnd.append("# This File Date  : " + strftime("%Y-%m-%d %H:%M:%S", gmtime()) + ""+ "\n")
    listEnd.append("# Update Frequency: 24 hours"+ "\n")
    listEnd.append("# Entries         : " + str(len(base_list)) + ""+ "\n")
    listEnd.append("#"+ "\n")
    listEnd.append("# (C) 2011-" + strftime("%Y", gmtime()) + " HybridNetworks Ltd. -- All Rights Reserved"+ "\n")
    listEnd.append("#"+ "\n")
    listEnd.append("# ============================================================"+ "\n")
    listEnd.append("#"+ "\n")
    listEnd.append("/ip firewall address-list"+ "\n")

    for i in base_list:
        listEnd.append("add list=WHATSAPP-CIDR comment=WHATSAPP-CIDR address=" + i)

    finalFile = open("WhatsApp/whatsapp_cidr_ipv4.rsc", "w+", encoding='utf-8', newline='\n')
    finalFile.writelines(listEnd)
    finalFile.close()


################################################################################
# Save File
################################################################################


def saveFileList(base_list, format) -> None:
    listEnd = []
    listEnd.append("# ============================================================"+ "\n")
    listEnd.append("#"+ "\n")
    listEnd.append("# whatsapp_cidr_ipv4"+ "\n")
    listEnd.append("#"+ "\n")
    listEnd.append("# ipv4 hash:net ipset"+ "\n")
    listEnd.append("#"+ "\n")
    listEnd.append("# List of the WhatsApp server IP addresses and ranges."+ "\n")
    listEnd.append("#"+ "\n")
    listEnd.append("# Maintainer      : Meta"+ "\n")
    listEnd.append("# Maintainer URL  : https://about.meta.com/"+ "\n")
    listEnd.append("# List source URL : https://developers.facebook.com/docs/whatsapp/guides/network-requirements/"+ "\n")
    listEnd.append("#"+ "\n")
    listEnd.append("# Category        : servers"+ "\n")
    listEnd.append("# Version         : 1"+ "\n")
    listEnd.append("#"+ "\n")
    listEnd.append("# This File Date  : " + strftime("%Y-%m-%d %H:%M:%S", gmtime()) + "\n")
    listEnd.append("# Update Frequency: 24 hours"+ "\n")
    listEnd.append("# Entries         : " + str(len(base_list)) + "\n")
    listEnd.append("#"+ "\n")
    listEnd.append("# (C) 2011-" + strftime("%Y", gmtime()) + " HybridNetworks Ltd. -- All Rights Reserved"+ "\n")
    listEnd.append("#"+ "\n")
    listEnd.append("# ============================================================"+ "\n")
    listEnd.append("#"+ "\n")
    listEnd.extend(base_list)

    finalFile = open("WhatsApp/whatsapp_cidr_ipv4." + format, "w+", encoding='utf-8', newline='\n')
    finalFile.writelines(listEnd)
    finalFile.close()


################################################################################
# Save File List Domain
################################################################################


def saveFileListDomain(base_list, format) -> None:
    listEnd = []
    listEnd.append("# ============================================================"+ "\n")
    listEnd.append("#"+ "\n")
    listEnd.append("# whatsapp_domainlist"+ "\n")
    listEnd.append("#"+ "\n")
    listEnd.append("# subdomains.domain"+ "\n")
    listEnd.append("#"+ "\n")
    listEnd.append("# List of the WhatsApp server domain and subdomains."+ "\n")
    listEnd.append("#"+ "\n")
    listEnd.append("# Maintainer      : SecurityTrails"+ "\n")
    listEnd.append("# Maintainer URL  : https://securitytrails.com/"+ "\n")
    listEnd.append("# List source URL : https://securitytrails.com/list/apex_domain/whatsapp.com"+ "\n")
    listEnd.append("# List source URL : https://securitytrails.com/list/apex_domain/whatsapp.net"+ "\n")
    listEnd.append("#"+ "\n")
    listEnd.append("# Category        : domains"+ "\n")
    listEnd.append("# Version         : 2"+ "\n")
    listEnd.append("#"+ "\n")
    listEnd.append("# This File Date  : " + strftime("%Y-%m-%d %H:%M:%S", gmtime()) + "\n")
    listEnd.append("# Update Frequency: 14th/month"+ "\n")
    listEnd.append("# Entries         : " + str(len(base_list)) + "\n")
    listEnd.append("#"+ "\n")
    listEnd.append("# (C) 2011-" + strftime("%Y", gmtime()) + " HybridNetworks Ltd. -- All Rights Reserved"+ "\n")
    listEnd.append("#"+ "\n")
    listEnd.append("# ============================================================"+ "\n")
    listEnd.append("#"+ "\n")
    listEnd.extend(base_list)

    finalFile = open("WhatsApp/whatsapp_domainlist." + format, "w+", encoding='utf-8', newline='\n')
    finalFile.writelines(listEnd)
    finalFile.close()


################################################################################
# Download ZIP file from https://developers.facebook.com/
################################################################################


def parseTxt(intxt) -> None:
    re_ip_mask = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}')
    lst = []

    data_list = str(intxt, 'UTF-8').split("\r\n")
    for line in data_list:
        ip = re.findall(re_ip_mask, line)
        if ip:
            lst.append(str(line) + "\n")

    saveFileList(lst, "txt")
    saveFileList(lst, "netset")
    saveFileList(lst, "list")
    saveFileRSC(lst)


def startNow() -> None:
    url = 'https://developers.facebook.com/docs/whatsapp/guides/network-requirements/'
    # Create the binary string html containing the HTML source
    # response.read().decode('utf-8')
    html = requests.get(url).content.decode('utf-8')
    urls = re.findall("http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+", html)
    for item in urls:
        if item.find(".zip") != -1:
            item = item.replace("amp;", "")
            wget.download(item)

    time.sleep(3)

    mypath = pathlib.Path(__file__).parent.absolute()
    f = []
    for (dirpath, dirnames, filenames) in walk(mypath):
        f.extend(filenames)
        break

    for fs in f:
        if fs.find(".zip") != -1:
            with ZipFile(fs) as zf:
                for file in zf.namelist():
                    if "__MACOSX" not in file:
                        print(file)
                        zipa = ZipFile(fs)
                        txtf = zipa.read(file)
                        zipa.close()

    cleanZip()
    parseTxt(txtf)


################################################################################
# Security Trails API from https://securitytrails.com/
################################################################################


def startNowDomains() -> None:

    # Check that it is working
    try:
        st.ping()
    except SecurityTrailsError:
        print('Ping failed')
        sys.exit(1)
    
    subdomains_wacom = st.domain_subdomains('whatsapp.com')
    subdomains_wanet = st.domain_subdomains('whatsapp.net')
    subdomains_wame = st.domain_subdomains('wa.me')
    subdomains_wabiz = st.domain_subdomains('whatsapp.biz')

    lst = []

    try:
        lstxt_wacom = re.search("'subdomains': (.+?)}", str(subdomains_wacom)).group(1)
        lstxt_wacom = lstxt_wacom.replace("[", "").replace("]", "").replace("'", "").replace(",", "")
        lstxt_wacom = list(lstxt_wacom.split(" "))

        lstxt_wanet = re.search("'subdomains': (.+?)}", str(subdomains_wanet)).group(1)
        lstxt_wanet = lstxt_wanet.replace("[", "").replace("]", "").replace("'", "").replace(",", "")
        lstxt_wanet = list(lstxt_wanet.split(" "))

        lstxt_wame = re.search("'subdomains': (.+?)}", str(subdomains_wame)).group(1)
        lstxt_wame = lstxt_wame.replace("[", "").replace("]", "").replace("'", "").replace(",", "")
        lstxt_wame = list(lstxt_wame.split(" "))

        lstxt_wabiz = re.search("'subdomains': (.+?)}", str(subdomains_wabiz)).group(1)
        lstxt_wabiz = lstxt_wabiz.replace("[", "").replace("]", "").replace("'", "").replace(",", "")
        lstxt_wabiz = list(lstxt_wabiz.split(" "))

    except Exception as e:
        raise
    else:
        pass
    finally:
        pass

    for line in lstxt_wacom:
        lst.append(str(line) + ".whatsapp.com" + "\n")

    for line in lstxt_wanet:
        lst.append(str(line) + ".whatsapp.net" + "\n")

    for line in lstxt_wame:
        lst.append(str(line) + ".wa.me" + "\n")

    for line in lstxt_wabiz:
        lst.append(str(line) + ".whatsapp.biz" + "\n")

    saveFileListDomain(lst, "txt")


################################################################################
# Main Function
################################################################################


async def main() -> None:
    access_token = os.getenv("ACCESS_TOKEN")
    if not access_token:
        # access_token = os.getenv("GITHUB_TOKEN")
        raise Exception("A personal access token is required to proceed!")
    exclude_repos = os.getenv("EXCLUDED")
    exclude_repos = ({x.strip() for x in exclude_repos.split(",")}
                     if exclude_repos else None)
    exclude_langs = os.getenv("EXCLUDED_LANGS")
    exclude_langs = ({x.strip() for x in exclude_langs.split(",")}
                     if exclude_langs else None)
    generate_output_folder()
    startNow()
    if strftime("%d", gmtime()) in '14':
        startNowDomains()


if __name__ == "__main__":
    asyncio.run(main())
