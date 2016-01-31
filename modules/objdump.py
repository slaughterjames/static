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
Dumps all headers, disassembled data from an ELF file using objdump
***END DESCRIPTION***
'''
def POE(logdir, target, logging, debug):

    if (logging == True): 
        LOG = logger() 
    newlogentry = ''
    objdump_dump = ''
    objdump_output_data = ''
    output = logdir + 'Objdump.txt'

    FI = fileio()
    
    print '[*] Running objdump against: ' + target.filename + '.  This may take a few moments, please be patient.'
    if (logging == True):
        newlogentry = 'Running objdump against: <strong>' + target.filename + '</strong>'
        LOG.WriteLog(logdir, target.filename, newlogentry)

    subproc = subprocess.Popen('objdump -x -S -s -D ' + target.filename, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for objdump_data in subproc.stdout.readlines():
         objdump_output_data += objdump_data
         if  (debug == True):
             print objdump_data    

    try:        
        FI.WriteLogFile(output, objdump_output_data)
        print '[*] Objdump data had been written to file here: ' + output
        if (logging == True):
            newlogentry = 'Objdump file has been generated to file here: <a href=\"' + output + '\"> Objdump Output </a>'
            LOG.WriteLog(logdir, target.filename, newlogentry)
    except:
        print '[x] Unable to write objdump data to file' 
        if (logging == True):
            newlogentry = 'Unable to write objdump data to file'
            LOG.WriteLog(logdir, target.filename, newlogentry)
        return -1

    return 0
