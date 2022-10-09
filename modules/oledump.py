#python imports
import sys
import os
import subprocess
from termcolor import colored

#programmer generated imports
from logger import logger
from fileio import fileio

'''
***BEGIN DESCRIPTION***
Type: Office - Description: Uses oledump to extract any ole object from a Microsoft Office file.
***END DESCRIPTION***
'''
def POE(POE):

    if (POE.logging == True): 
        LOG = logger() 
    newlogentry = ''
    oledump_dump = ''
    oledump_output_data = ''
    oledump_dump_data = ''
    output = POE.logdir + 'oledump.txt'

    if (POE.logging == True):
        newlogentry = 'Module: oledump'           
        LOG.WriteStrongLog(POE.logdir, POE.targetfilename, newlogentry)

    FI = fileio()

    print (colored('\r\n[*] Running oledump against: ' + POE.target, 'white', attrs=['bold']))

    subproc = subprocess.Popen('python3 /opt/oledump/oledump.py ' +  POE.target + ' > ' + output, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for oledump_data in subproc.stdout.readlines():
         oledump_output_data += str(oledump_data)
         if  (POE.debug == True):
             print (oledump_data)

    print (colored('[*] oledump data has been generated to file here: ', 'green') + colored(output, 'blue', attrs=['bold']))

    if ((POE.logging == True) and (POE.nolinksummary == False)):
        newlogentry = 'oledump file has been generated to file here: <a href=\"' + output + '\"> oledump Output </a>'
        LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)

    return 0
