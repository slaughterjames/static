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
Type: Office - Description: Uses rtfdump to extract any ole object data from a Microsoft RTF file.
***END DESCRIPTION***
'''
def POE(POE):

    if (POE.logging == True): 
        LOG = logger() 
    newlogentry = ''
    rtfdump_dump = ''
    rtfdump_output_data = ''
    rtfdump_dump_data = ''
    output = POE.logdir + 'rtfdump.txt'

    if (POE.logging == True):
        newlogentry = 'Module: rtfdump'           
        LOG.WriteStrongLog(POE.logdir, POE.targetfilename, newlogentry)

    if (POE.debug == True):
        print ('[DEBUG] POE.extension: ' + POE.extension)

    if ((POE.extension.find('rtf') == -1) and (POE.extension.find('RTF') == -1)):
        print (colored('\r\n[x] Unable to execute rtfdump - file must be Microsoft RTF.', 'red', attrs=['bold']))
        newlogentry = 'Unable to execute rtfdump - file must be Microsoft RTF'
        LOG.WriteStrongSubLog(POE.logdir, POE.targetfilename, newlogentry)
        return -1

    FI = fileio()

    print (colored('\r\n[*] Running rtfdump against: ' + POE.target, 'white', attrs=['bold']))

    subproc = subprocess.Popen('/opt/rtfdump/rtfdump.py ' +  POE.target + ' > ' + output, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for rtfdump_data in subproc.stdout.readlines():
         rtfdump_output_data += str(rtfdump_data)
         if  (POE.debug == True):
             print (rtfdump_data)

    print (colored('[*] rtfdump data has been generated to file here: ', 'green') + colored(output, 'blue', attrs=['bold']))

    if ((POE.logging == True) and (POE.nolinksummary == False)):
        newlogentry = 'rtfdump data has been generated to file here: <a href=\"' + output + '\"> rtfdump Output </a>'
        LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)

    return 0
