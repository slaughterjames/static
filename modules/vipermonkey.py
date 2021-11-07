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
Type: Office - Description: Runs Vipermonkey against an office sample.
***END DESCRIPTION***
'''
def POE(POE):

    output = POE.logdir + 'vmonkey.txt'    
    vmonkey_data = ''
    vmonkey_output_data = ''

    if (POE.logging == True): 
        LOG = logger() 
    newlogentry = ''

    if (POE.logging == True):
        newlogentry = 'Module: vipermonkey'           
        LOG.WriteStrongLog(POE.logdir, POE.targetfilename, newlogentry)

    if (len(POE.macros) == 0):
        print (colored('\r\n[-] Unable to execute Vipermonkey - no macros identified - skipping.', 'yellow', attrs=['bold']))
        if (POE.logging == True):
            newlogentry = 'Unable to execute Vipermonkey - no macros identified - skipping.'
            LOG.WriteStrongSubLog(POE.logdir, POE.targetfilename, newlogentry)
        return -1

    FI = fileio()
    
    print (colored('\r\n[*] Running vipermonkey against: ' + POE.target, 'white', attrs=['bold']))

    subproc = subprocess.Popen('/opt/static/dockermonkey.sh ' + POE.target + ' > ' + output, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for vmonkey_data in subproc.stdout.readlines():        
        if (POE.debug == True):
            print ('VMonkey: ' + str(vmonkey_data) + '\n')

    print (colored('[*] vipermonkey data has been generated to file here: ', 'green') + colored(output, 'blue', attrs=['bold']))
    if ((POE.logging == True) and (POE.nolinksummary == False)):
        newlogentry = 'vipermonkey data has been generated to file here: <a href=\"' + output + '\"> vipermonkey </a>'           
        LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry) 

    return 0
