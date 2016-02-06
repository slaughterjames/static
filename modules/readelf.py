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
Uses readelf to pull the header information from an ELF file
***END DESCRIPTION***
'''
def POE(logdir, target, logging, debug):

    if (logging == True): 
        LOG = logger() 
    newlogentry = ''
    readelf_dump = ''
    readelf_output_data = ''
    output = logdir + 'Readelf.txt'

    FI = fileio()
    
    if (logging == True):
        newlogentry = 'Running readelf against: <strong>' + target.filename + '</strong>'
        LOG.WriteLog(logdir, target.filename, newlogentry)

    subproc = subprocess.Popen('readelf -h ' + target.filename, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for readelf_data in subproc.stdout.readlines():
         readelf_output_data += readelf_data
         if  (debug == True):
             print readelf_data    

    try:        
        FI.WriteLogFile(output, readelf_output_data)
        print '[*] Readelf data had been written to file here: ' + output
        if (logging == True):
            newlogentry = 'Readelf file has been generated to file here: <a href=\"' + output + '\"> Readelf Output </a>'
            LOG.WriteLog(logdir, target.filename, newlogentry)
    except:
        print '[x] Unable to write readelf data to file' 
        if (logging == True):
            newlogentry = 'Unable to write readelf data to file'
            LOG.WriteLog(logdir, target.filename, newlogentry)
        return -1

    return 0
