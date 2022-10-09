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
Type: Office - Description: Uses lnkinfo to extract data from a Microsoft Windows Shortcut file.
***END DESCRIPTION***
'''
def POE(POE):

    if (POE.logging == True): 
        LOG = logger() 
    newlogentry = ''
    lnkinfo_dump = ''
    lnkinfo_output_data = ''
    lnkinfo_dump_data = ''
    output = POE.logdir + 'lnkdump.txt'

    if (POE.logging == True):
        newlogentry = 'Module: lnkdump'           
        LOG.WriteStrongLog(POE.logdir, POE.targetfilename, newlogentry)

    if (POE.debug == True):
        print ('[DEBUG] POE.extension: ' + POE.extension)

    if ((POE.extension.find('lnk') == -1) and (POE.extension.find('LNK') == -1)):
        print (colored('\r\n[x] Unable to execute lnkdump - file must be Microsoft Windows Shortcut.', 'red', attrs=['bold']))
        newlogentry = 'Unable to execute lnkdump - file must be Microsoft Windows Shortcut.'
        LOG.WriteStrongSubLog(POE.logdir, POE.targetfilename, newlogentry)
        return -1

    FI = fileio()

    print (colored('\r\n[*] Running lnkdump against: ' + POE.target, 'white', attrs=['bold']))

    subproc = subprocess.Popen('lnkinfo ' +  POE.target + ' > ' + output, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for rtfdump_data in subproc.stdout.readlines():
         rtfdump_output_data += str(rtfdump_data)
         if  (POE.debug == True):
             print (rtfdump_data)

    print (colored('[*] lnkdump data has been generated to file here: ', 'green') + colored(output, 'blue', attrs=['bold']))

    if ((POE.logging == True) and (POE.nolinksummary == False)):
        newlogentry = 'lnkdump data has been generated to file here: <a href=\"' + output + '\"> lnkdump Output </a>'
        LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)

    return 0
