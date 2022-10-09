#python imports
import sys
import os
import subprocess
import json
import time
import requests
from termcolor import colored

#third-party imports
#No third-party imports

#programmer generated imports
from logger import logger
from fileio import fileio

'''
***BEGIN DESCRIPTION***
Type: Elf - Description: Uses readelf to pull the header information from an ELF file.
***END DESCRIPTION***
'''
def POE(POE):

    if (POE.logging == True): 
        LOG = logger() 
    newlogentry = ''
    readelf_dump = ''
    readelf_output_data = ''
    output = POE.logdir + 'Readelf.txt'

    FI = fileio()

    if (POE.logging == True):
        newlogentry = 'Module: readelf'           
        LOG.WriteStrongLog(POE.logdir, POE.targetfilename, newlogentry)

    print (colored('\r\n[*] Running readelf against: ' + POE.target, 'white', attrs=['bold']))

    subproc = subprocess.Popen('readelf -h ' +  POE.target + ' > ' + output, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for readelf_data in subproc.stdout.readlines():
         readelf_output_data += str(readelf_data)
         if  (POE.debug == True):
             print (readelf_data)

    print (colored('[*] Readelf data has been generated to file here: ', 'green') + colored(output, 'blue', attrs=['bold']))

    if ((POE.logging == True) and (POE.nolinksummary == False)):
        newlogentry = 'Readelf file has been generated to file here: <a href=\"' + output + '\"> Readelf Output </a>'
        LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)

    return 0
