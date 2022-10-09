#python imports
import sys
import os
import subprocess
from termcolor import colored

#third-party imports
from oletools.olevba import VBA_Parser, TYPE_OLE, TYPE_OpenXML, TYPE_Word2003_XML, TYPE_MHTML

#programmer generated imports
from logger import logger
from fileio import fileio

'''
***BEGIN DESCRIPTION***
Type: Office - Description: Uses olevba to extract any ole object from a Microsoft Office file.
***END DESCRIPTION***
'''
def POE(POE):

    if (POE.logging == True): 
        LOG = logger() 
    newlogentry = ''
    ole_dump = ''
    ole_output_data = ''
    ole_dump_data = ''
    output = POE.logdir + 'extractoleobj.txt'

    if (POE.logging == True):
        newlogentry = 'Module: extractoleobj'           
        LOG.WriteStrongLog(POE.logdir, POE.targetfilename, newlogentry)

    FI = fileio()

    print (colored('\r\n[*] Running extractoleobj against: ' + POE.target, 'white', attrs=['bold']))

    subproc = subprocess.Popen('oleobj ' +  POE.target + ' > ' + output, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for ole_data in subproc.stdout.readlines():
         ole_output_data += str(ole_data)
         if  (POE.debug == True):
             print (ole_data)

    print (colored('[*] extractoleobj data has been generated to file here: ', 'green') + colored(output, 'blue', attrs=['bold']))

    if ((POE.logging == True) and (POE.nolinksummary == False)):
        newlogentry = 'extractoleobj file has been generated to file here: <a href=\"' + output + '\"> extractoleobj Output </a>'
        LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)

    return 0
