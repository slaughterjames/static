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
Type: Elf - Description: Dumps all headers, disassembled data from an ELF file using objdump.
***END DESCRIPTION***
'''
def POE(POE):

    if (POE.logging == True): 
        LOG = logger() 
    newlogentry = ''
    objdump_data = ''
    objdump_output_data = ''
    output = POE.logdir + 'objdump.txt'

    FI = fileio()

    if (POE.logging == True):
        newlogentry = 'Module: objdump'           
        LOG.WriteStrongLog(POE.logdir, POE.targetfilename, newlogentry)

    print (colored('\r\n[*] Running objdump against: ' + POE.target + '.  This may take a few moments, please be patient...', 'white', attrs=['bold']))

    subproc = subprocess.Popen('objdump -x -S -s -D ' + POE.target + ' > ' + output, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for objdump_data in subproc.stdout.readlines():
         objdump_output_data += str(objdump_data)
         if  (POE.debug == True):
             print (objdump_data)

    print (colored('[*] Objdump data has been generated to file here: ', 'green') + colored(output, 'blue', attrs=['bold']))

    if ((POE.logging == True) and (POE.nolinksummary == False)):
        newlogentry = 'Objdump file has been generated to file here: <a href=\"' + output + '\"> Objdump Output </a>'
        LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)

    return 0
