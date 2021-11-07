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
Type: Triage - Description: Runs Yara rules against the sample.
***END DESCRIPTION***
'''
def POE(POE):

    output = POE.logdir + 'yara.txt'    
    yara_data = ''
    yara_output_data = ''

    if (POE.logging == True): 
        LOG = logger() 
    newlogentry = ''

    if (POE.logging == True):
        newlogentry = 'Module: yara'           
        LOG.WriteStrongLog(POE.logdir, POE.targetfilename, newlogentry)

    FI = fileio()
    
    print (colored('\r\n[*] Running Yara against: ' + POE.target, 'white', attrs=['bold']))

    subproc = subprocess.Popen('yara -w -g -m ' + POE.yararulesdirectory + '/index.yar ' + '\"' + POE.target + '\" > ' + output, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for yara_data in subproc.stdout.readlines():        
        if (POE.debug == True):
            print ('Yara: ' + str(yara_data) + '\n')

    print (colored('[*] Yara data had been written to file here: ', 'green') + colored(output, 'blue', attrs=['bold']))
    if ((POE.logging == True) and (POE.nolinksummary == False)):
        newlogentry = 'Yara data has been generated to file here: <a href=\"' + output + '\"> Yara </a>'           
        LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)

    try:
        count = len(open(output).readlines())
        print (colored('[*] Yara has returned: ' + str(count) + ' results.', 'green', attrs=['bold']))
        if (POE.logging == True):
            newlogentry = 'Yara has returned: ' + str(count) + ' results.'          
            LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
    except:
        if (POE.logging == True):
            newlogentry = 'Unable to get results count.'           
            LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)        
 

    return 0
