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
Parses and shows the structure of a PDF file using Didier Stevens' pdf-parser.py
***END DESCRIPTION***
'''
def POE(logdir, target, logging, debug):

    if (logging == True): 
        LOG = logger() 
    newlogentry = ''
    strings_dump = ''
    strings_output_data = ''
    output = logdir + 'PDFParse.txt'

    FI = fileio()
    
    if (logging == True):
        newlogentry = 'Running pdf-parse against: <strong>' + target.filename + '</strong>'
        LOG.WriteLog(logdir, target.filename, newlogentry)

    subproc = subprocess.Popen('/etc/static/pdf-parser.py -c ' + target.filename, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for strings_data in subproc.stdout.readlines():
         strings_output_data += strings_data
         if  (debug == True):
             print strings_data    

    try:        
        FI.WriteLogFile(output, strings_output_data)
        print '[*] PDF Parse data had been written to file here: ' + output
        if (logging == True):
            newlogentry = 'PDF Parse data has been generated to file here: <a href=\"' + output + '\"> PDF Parse Output </a>'
            LOG.WriteLog(logdir, target.filename, newlogentry)
    except:
        print '[x] Unable to write PDF Parse data to file' 
        if (logging == True):
            newlogentry = 'Unable to write PDF Parse data to file'
            LOG.WriteLog(logdir, target.filename, newlogentry)
        return -1

    return 0
