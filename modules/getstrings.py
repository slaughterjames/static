#python imports
import sys
import os
import subprocess

#third-party imports
#No third-party imports

#programmer generated imports
from logger import logger
from fileio import fileio

'''
***BEGIN DESCRIPTION***
Type: Triage - Extracts the strings from a file sample.
***END DESCRIPTION***
'''
def POE(logdir, target, logging, debug):

    if (logging == True): 
        LOG = logger() 
    newlogentry = ''
    strings_dump = ''
    strings_output_data = ''
    output = logdir + 'Strings.txt'

    FI = fileio()
    
    if (logging == True):
        newlogentry = 'Running strings against: <strong>' + target.target + '</strong>'
        LOG.WriteLog(logdir, target.filename, newlogentry)

    subproc = subprocess.Popen('strings -a ' + target.target, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for strings_data in subproc.stdout.readlines():
         strings_output_data += strings_data
         if  (debug == True):
             print strings_data    

    try:        
        FI.WriteLogFile(output, strings_output_data)
        print '[*] Strings data had been written to file here: ' + output
        if (logging == True):
            newlogentry = 'Strings file has been generated to file here: <a href=\"' + output + '\"> Strings Output </a>'
            LOG.WriteLog(logdir, target.filename, newlogentry)
    except:
        print '[x] Unable to write strings data to file' 
        if (logging == True):
            newlogentry = 'Unable to write strings data to file'
            LOG.WriteLog(logdir, target.filename, newlogentry)
        return -1

    return 0
