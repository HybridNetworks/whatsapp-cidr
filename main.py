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

st = SecurityTrails('4BmIMfy1j7N8BnXQr2cd0TehnZSMY2W8')

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

def saveFileRSC(clist):
    listEnd=[]
    for i in clist:
        listEnd.append("add list=WHATSAPP-CIRD comment=WHATSAPP-CIRD address=" + i)

    finalFile = open("WhatsApp/whatsapp_cidr_ipv4.rsc", "w")
    finalFile.write("# ============================================================\n")
    finalFile.write("#\n")
    finalFile.write("# whatsapp_cidr\n")
    finalFile.write("#\n")
    finalFile.write("# ipv4 mikrotik address-list\n")
    finalFile.write("#\n")
    finalFile.write("# List of the WhatsApp server IP addresses and ranges.\n")
    finalFile.write("#\n")
    finalFile.write("# Maintainer      : Meta\n")
    finalFile.write("# Maintainer URL  : https://about.facebook.com/\n")
    finalFile.write("# List source URL : https://developers.facebook.com/docs/whatsapp/guides/network-requirements/\n")
    finalFile.write("#\n")
    finalFile.write("# Category        : servers\n")
    finalFile.write("# Version         : 1\n")
    finalFile.write("#\n")
    finalFile.write("# This File Date  : " + strftime("%Y-%m-%d %H:%M:%S", gmtime()) + "\n")
    finalFile.write("# Update Frequency: 24 hours\n")
    finalFile.write("# Entries         : " + str(len(clist)) + "\n")
    finalFile.write("#\n")
    finalFile.write("# (C) 2011-" + strftime("%Y", gmtime()) + " HybridNetworks Ltd. -- All Rights Reserved\n")
    finalFile.write("#\n")
    finalFile.write("# ============================================================\n")
    finalFile.write("#\n")
    finalFile.write("/ip firewall address-list" + "\n")
    finalFile.writelines(listEnd)
    finalFile.close() 


################################################################################
# Save File
################################################################################


def saveFileList(clist, format) -> None:
    finalFile = open("WhatsApp/whatsapp_cidr_ipv4." + format, "w")
    finalFile.write("# ============================================================\n")
    finalFile.write("#\n")
    finalFile.write("# whatsapp_cidr\n")
    finalFile.write("#\n")
    finalFile.write("# ipv4 hash:net ipset\n")
    finalFile.write("#\n")
    finalFile.write("# List of the WhatsApp server IP addresses and ranges.\n")
    finalFile.write("#\n")
    finalFile.write("# Maintainer      : Meta\n")
    finalFile.write("# Maintainer URL  : https://about.facebook.com/\n")
    finalFile.write("# List source URL : https://developers.facebook.com/docs/whatsapp/guides/network-requirements/\n")
    finalFile.write("#\n")
    finalFile.write("# Category        : servers\n")
    finalFile.write("# Version         : 1\n")
    finalFile.write("#\n")
    finalFile.write("# This File Date  : " + strftime("%Y-%m-%d %H:%M:%S", gmtime()) + "\n")
    finalFile.write("# Update Frequency: 24 hours\n")
    finalFile.write("# Entries         : " + str(len(clist)) + "\n")
    finalFile.write("#\n")
    finalFile.write("# (C) 2011-" + strftime("%Y", gmtime()) + " HybridNetworks Ltd. -- All Rights Reserved\n")
    finalFile.write("#\n")
    finalFile.write("# ============================================================\n")
    finalFile.write("#\n")
    finalFile.writelines(clist)
    finalFile.close()


################################################################################
# Save File List Domain
################################################################################


def saveFileListDomain(clist, format) -> None:
    finalFile = open("WhatsApp/whatsapp_domainlist." + format, "w")
    finalFile.write("# ============================================================\n")
    finalFile.write("#\n")
    finalFile.write("# whatsapp_domainlist\n")
    finalFile.write("#\n")
    finalFile.write("# subdomains.domain\n")
    finalFile.write("#\n")
    finalFile.write("# List of the WhatsApp server domain and subdomains.\n")
    finalFile.write("#\n")
    finalFile.write("# Maintainer      : Meta\n")
    finalFile.write("# Maintainer URL  : https://securitytrails.com/\n")
    finalFile.write("# List source URL : https://securitytrails.com/list/apex_domain/whatsapp.com\n")
    finalFile.write("# List source URL : https://securitytrails.com/list/apex_domain/whatsapp.net\n")
    finalFile.write("#\n")
    finalFile.write("# Category        : domains\n")
    finalFile.write("# Version         : 1\n")
    finalFile.write("#\n")
    finalFile.write("# This File Date  : " + strftime("%Y-%m-%d %H:%M:%S", gmtime()) + "\n")
    finalFile.write("# Update Frequency: 24 hours\n")
    finalFile.write("# Entries         : " + str(len(clist)) + "\n")
    finalFile.write("#\n")
    finalFile.write("# (C) 2011-" + strftime("%Y", gmtime()) + " HybridNetworks Ltd. -- All Rights Reserved\n")
    finalFile.write("#\n")
    finalFile.write("# ============================================================\n")
    finalFile.write("#\n")
    finalFile.writelines(clist)
    finalFile.close()


################################################################################
# Download ZIP file from https://developers.facebook.com/
################################################################################


def parseTxt(intxt) -> None:
    re_ip_mask = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}')
    lst = []

    data_list = str(intxt, 'UTF-8').split("\n")
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

    lst = []

    try:
        lstxt_wacom = re.search("'subdomains': (.+?)}", str(subdomains_wacom)).group(1)
        lstxt_wacom = lstxt_wacom.replace("[", "").replace("]", "").replace("'", "").replace(",", "")
        lstxt_wacom = list(lstxt_wacom.split(" "))

        lstxt_wanet = re.search("'subdomains': (.+?)}", str(subdomains_wanet)).group(1)
        lstxt_wanet = lstxt_wanet.replace("[", "").replace("]", "").replace("'", "").replace(",", "")
        lstxt_wanet = list(lstxt_wanet.split(" "))
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
    startNowDomains()


if __name__ == "__main__":
    asyncio.run(main())
