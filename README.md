Using Static v0.1

Static is an analysis framework for malware.  Rather than being a monolithic program, Static allows for the addition of individual scripts to handle specific scenarios.  Currently, Static supports plug scripts for the PE, ELF, MS Office and PDF file formats.

Installation of Static is relatively straight forward.  At the moment, the only supported operating system is Linux (testing has taken place exclusively on Ubuntu).  The easiest way to install static is by using the "get-static.sh" Bash script.  It will install the necessary prerequisites and additional Python modules needed.  The main files will be deposited in "/opt/static" and the add-in modules be placed in "/opt/static/modules".  When running "get-static.sh" you should see the following output:

~ $ sudo ./get-static.sh 
Installing Static on: LinuxMint
Architecture is: 64 bit
Version is: 17.2

 * INFO: Installing Static. Details logged to /var/log/static-install.log.
 * INFO: Updating the base APT repository package list... 
 * INFO: Upgrading all APT packages to latest versions...
 * INFO: Installing APT Package: python
 * INFO: Installing APT Package: python-dev
 * INFO: Installing APT Package: automake
 * INFO: Installing APT Package: python-pip
 * INFO: Installing APT Package: python-setuptools
 * INFO: Installing APT Package: python-magic
 * INFO: Installing Python Package: pefile
 * INFO: Installing Python Package: oletools
 * INFO: Installing Python Package: unidecode
 * INFO: Creating directories
 * INFO: Installing Static
 * INFO: Installing UserDB
 * INFO: Installing PDFId
 * INFO: Installing PDF Parser
 * INFO: ---------------------------------------------------------------
 * INFO: Static Installation Complete!
 * INFO: See documentation at https://REMnux.org/docs
 * INFO: Reboot for the settings to take full effect ("sudo reboot").
 * INFO: ---------------------------------------------------------------   

The "static.conf" file acts as a way to avoid hard-coding variables as much as possible for the logging functionality as well as for any modules being used by the tool.  Adjust directories for the automatic placement of logs or where modules are to be located.  The file is shown below.

'''
Static v0.1 - Copyright 2016 James Slaughter,
This file is part of Static v0.1.

Static v0.1 is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Static v0.1 is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Static v0.1.  If not, see <http://www.gnu.org/licenses/>.
'''

###Static v0.1 Configuration File

#Static Logging
logging false

#Static Log Directory
logdir <Your Log Directory>

#Static Modules Directory
modulesdir /opt/static/modules/ 

#Addins
fileaddin getstrings
peaddin staticpe
peaddin quickenum
officeaddin extractmacro
officeaddin Dridex122
officeaddin chrsearch
pdfaddin pdfparse
pdfaddin pdf_id
elfaddin objdump
elfaddin readelf

#END OF FILE

The "logging" setting establishes a custom logger for Static.  Even if not true, the "logdir" setting still needs to be set so the output from the various addins can be sent there.

The use of Static is relatively straight forward.  To bring up the help screen, execute "/opt/static/static.py" or "/opt/static/static.py --help".  The response will be as follows:

~ $ /opt/static/static.py --help
[*] Arguments: 
Usage: [required] --target --type --modules [all|specific] --output -- debug --listmodules --help
Example: /opt/static/static.py --target 123.exe --type pe --modules all --output /your/directory --debug
Required Arguments:
--target - file that will be analyzed
--type - pe, elf, office, pdf
--modules - all or specific
Optional Arguments:
--output - choose where you wish the output to be directed
--listmodules - prints a list of available modules and their descriptions
--debug - prints verbose output to the screen 
--help - You're looking at it!

All arguments are shown above with their descriptions.  "--target", "--type" and "modules" are required arguments.  The "--modules" argument can either be "all" for each supported type or a specific module.  At the moment, only one module at a time is supported using this method.

The output of "--listmodules" is shown below:

~ $ /opt/static/static.py --listmodules
[*] Arguments: 
listmodules: True

[*] getstrings
Extracts the strings from a file sample

[*] staticpe
Uses PEUtils to get the particulars on the submitted sample to give a jump start on reverse engineering

[*] quickenum
Quickly ennumerates the different sections of the PE file target and lists things like the compile time if available.

[*] extractmacro
Extract any macro code from a Microsoft Office file

[*] Dridex122
Analyzes known Dridex affiliate 12X faux MS-Word e-mail attachments

[*] pdfparse
Parses and shows the structure of a PDF file using Didier Stevens' pdf-parser.py

[*] pdf_id
Scans a PDF document for a given list of strings and count the occurrences (total and obfuscated) of each word

[*] objdump
Dumps all headers, disassembled data from an ELF file using objdump

[*] readelf
Uses readelf to pull the header information from an ELF file


To deploy Static against a target file without the logger or debugging enabled, the following command can be used.  Example output is shown.

$ /opt/static/static.py --target 983bv3.exe --type pe --modules all
[*] Arguments: 
target: 983bv3.exe
type: pe
modules: all
[-] Logger not active
[*] MD5 hash of file 983bv3.exe: 5bddf5271b1472eca61a6a2d66280020
[*] SHA256 hash of file 983bv3.exe: 8030e075bd21b43f759a7095f34773df6316a5c38ea2956e6acfa76d0e82bd84
[*] Fileheader: 983bv3.exe: PE32 executable (GUI) Intel 80386, for MS Windows

[*] Organize Modules

[*] Module virustotal located
[*] Module virustotal loaded successfully
[*] Executing module
[*] CURL - pulling the current VirusTotal data for sample 983bv3.exe
[*] Offline VirusTotal data can be found here: /home/static/983bv3.exe/VirusTotalReport.html
[*] The live VirusTotal data can be found here: https://www.virustotal.com/en/file/8030e075bd21b43f759a7095f34773df6316a5c38ea2956e6acfa76d0e82bd84/analysis/

[*] Module getstrings located
[*] Module getstrings loaded successfully
[*] Executing module
[*] Strings data had been written to file here: /home/static/983bv3.exe/Strings.txt

[*] Module staticpe located
[*] Module staticpe loaded successfully
[*] Executing module
[*] Signature Matches: None
[-] Unable to process DIRECTORY_ENTRY_EXPORT object:  PE instance has no attribute 'DIRECTORY_ENTRY_EXPORT'
[*] Dump file has been generated to file here: /home/static/983bv3.exe/FullDump.txt

[*] Module quickenum located
[*] Module quickenum loaded successfully
[*] Executing module
[*] File compile time: 2015-10-08 11:49:09
[*] Section Name: .text
    Virtual Address: 0x1000
    Virtual Size: 0xe334
    Raw Data Size: 58368
[*] Section Name: .rdata
    Virtual Address: 0x10000
    Virtual Size: 0x6f9a
    Raw Data Size: 28672
[*] Section Name: .data
    Virtual Address: 0x17000
    Virtual Size: 0x5504
    Raw Data Size: 14848
[*] Section Name: .tima
    Virtual Address: 0x1d000
    Virtual Size: 0x10b2b
    Raw Data Size: 68608
[*] Section Name: .texa
    Virtual Address: 0x2e000
    Virtual Size: 0x2f0b
    Raw Data Size: 12288
[*] Section Name: .tora
    Virtual Address: 0x31000
    Virtual Size: 0x19ca
    Raw Data Size: 6656
[*] Section Name: .dosa
    Virtual Address: 0x33000
    Virtual Size: 0x1783
    Raw Data Size: 6144
[*] Section Name: .gafe
    Virtual Address: 0x35000
    Virtual Size: 0x571
    Raw Data Size: 1536
[*] Section Name: .rsrc
    Virtual Address: 0x36000
    Virtual Size: 0x1aa08
    Raw Data Size: 109568
[*] Section Name: .reloc
    Virtual Address: 0x51000
    Virtual Size: 0x1e00
    Raw Data Size: 7680
[*] Quickenum data had been written to file here: /home/static/983bv3.exe/Quickenum.txt

To deploy Static against a target using only a single module, the following syntax would be used:

$ /opt/static/static.py --target PO_48847.DOC --type office --modules extractmacro
[*] Arguments: 
target: PO_48847.DOC
type: office
modules: extractmacro
[-] Logger not active
[*] MD5 hash of file PO_48847.DOC: c6cd52b59fc772edde4df5d4058524fe
[*] SHA256 hash of file PO_48847.DOC: 9f598aa8751d9a7b5a6afe1d6e1e930d92c2131bd2f7c1839ba94307934b1e91
[*] Fileheader: PO_48847.DOC: Composite Document File V2 Document, Little Endian, Os: Windows, Version 6.2, Code page: 1251, Author: 1, Template: Normal, Last Saved By: 1, Revision Number: 2, Name of Creating Application: Microsoft Office Word, Create Time/Date: Tue Oct 20 06:57:00 2015, Last Saved Time/Date: Tue Oct 20 06:57:00 2015, Number of Pages: 1, Number of Words: 0, Number of Characters: 0, Security: 0

[*] Organize Modules
[*] Module extractmacro

[*] Module extractmacro located
[*] Module extractmacro loaded successfully
[*] Executing module
[*] VBA macros found - Extracting...

[*] Macro ThisDocument.cls extracted to: /home/static/PO_48847.DOC/ThisDocument.cls
[x] Current macro - unable print Filename, OLE stream or VBA filename due to encoding issue: (Unicode?) local variable 'LOG' referenced before assignment
[*] Macro Module1.bas extracted to: /home/static/rafalelogs/PO_48847.DOC/Module1.bas
[x] Current macro - unable print Filename, OLE stream or VBA filename due to encoding issue: (Unicode?) local variable 'LOG' referenced before assignment
[*] Macro Module2.bas extracted to: /home/static/PO_48847.DOC/Module2.bas
[x] Current macro - unable print Filename, OLE stream or VBA filename due to encoding issue: (Unicode?) local variable 'LOG' referenced before assignment
[*] Macro Module3.bas extracted to: /home/static/PO_48847.DOC/Module3.bas
[x] Current macro - unable print Filename, OLE stream or VBA filename due to encoding issue: (Unicode?) local variable 'LOG' referenced before assignment
Macro List
/home/static/PO_48847.DOC/ThisDocument.cls
/home/static/PO_48847.DOC/Module1.bas
/home/static/PO_48847.DOC/Module2.bas
/home/static/PO_48847.DOC/Module3.bas

Given Static was designed to be modular, you can easily develop your own addins quickly.  A template file has been included in the package, "template.py".  The template is shown below:

#python imports
#standard widely used classes, add  or remove as needed
import sys
import os
import subprocess

#third-party imports

#programmer generated imports
#This is my log generator, you could easily replace with your own
from logger import logger
#This is the static file read and log write class - again, you could use the Python 
#standard or implement your own
from fileio import fileio

'''
***BEGIN DESCRIPTION***
Add a description of what your addin module does
***END DESCRIPTION***
'''
def POE(logdir, target, logging, debug):
#POE = Point Of Entry - where the main static code interfaces with this module
#logdir - Any potential output will go here
#target - Target file to be analyzed.  Class attributes include MD5, SHA256, filename and header.  Example, "target.filename"
#logging - The logging flag,  it it has been turned on, logging can occur whether using the provided logger class or you use your own.
#debug - The debug flag, if turned on, debug logging can be added

    #Add your code here

    #Example Log Line
    #if (logging == True): 
    #    LOG = logger() 
    #newlogentry = ''
    #if (logging == True):
        #newlogentry = 'My log line'
        #LOG.WriteLog(logdir, target.filename, newlogentry)
    

    return 0

To enable a newly created module, it needs to be added to the "static.conf" file in one of the following formats without the file extention:

fileaddin newfile
peaddin newfile
officeaddin newfile
pdfaddin newfile
elfaddin newfile

File listing:
controller.py
fileclasses.py
fileio.py
FILtriage.py
logger.py
static.conf
static.py

Module Listing:
Dridex122.py
chrsearch.py
extractmacro.py
getstrings.py
objdump.py
pdf_id.py
pdfparse.py
quickenum.py
readelf.py
staticpe.py

If you have any questions or concerns or wish to report a bug, send a message to slaughter.james@gmail.com or on Twitter at @slaughterjames


