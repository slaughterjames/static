#python imports
import sys
import os
import subprocess
from datetime import datetime
from termcolor import colored

#third-party imports
import pefile
import peutils

#programmer generated imports
#from fileclasses import peclass
from logger import logger
from fileio import fileio

'''
***BEGIN DESCRIPTION***
Type: PE - Description: Uses PEUtils to get the particulars on the submitted sample to give a jump start on reverse engineering.
***END DESCRIPTION***
'''
def POE(POE):
            
    newlogentry = ''
    full_dump = ''
    matches = ''
    timestamp = ''
    dt_object = ''
    output = POE.logdir + 'PEDump.txt'
    if (POE.logging == True): 
        LOG = logger()

    FI = fileio()
    PEX = pefile.PE(POE.target)

    if (POE.logging == True):
        newlogentry = 'Module: staticpe'           
        LOG.WriteStrongLog(POE.logdir, POE.targetfilename, newlogentry)

    print (colored('\r\n[*] Running staticpe against: ' + POE.target, 'white', attrs=['bold']))

    print (colored('[*] File Sections: ', 'green', attrs=['bold']))
    newlogentry = 'File Sections:'
    LOG.WriteStrongSubLog(POE.logdir, POE.targetfilename, newlogentry)

    for section in PEX.sections:
        print ('[-] ' + section.Name.decode('ascii') + ' Virtual Address: ' + str(hex(section.VirtualAddress)) + ' Virtual Size: ' + str(hex(section.Misc_VirtualSize)) + ' Raw Data Size: ' +  str(section.SizeOfRawData))
        newlogentry = section.Name.decode('ascii') + ' Virtual Address: ' + str(hex(section.VirtualAddress)) + ' Virtual Size: ' + str(hex(section.Misc_VirtualSize)) + ' Raw Data Size: ' +  str(section.SizeOfRawData)
        LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)

    timestamp = PEX.FILE_HEADER.TimeDateStamp
    dt_object = datetime.fromtimestamp(timestamp)
    print ('[*] TimeDateStamp (Local): ' + str(dt_object))
    newlogentry = 'TimeDateStamp (Local): ' + str(dt_object)
    LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
  
    try:
        for entry in PEX.DIRECTORY_ENTRY_IMPORT: 
            for imp in entry.imports:
                if (POE.debug == True):
                    print ('[DEBUG] imp address and name: ' + str(hex(imp.address)) +  str(imp.name))
    except Exception as e:
        print ('[-] Unable to process DIRECTORY_ENTRY_IMPORT object: ', e)
        if (POE.logging == True):
            newlogentry = 'Unable to process DIRECTORY_ENTRY_IMPORT object'
            LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
  
    try:
        for exp in PEX.DIRECTORY_ENTRY_EXPORT.symbols:
            if (POE.debug == True):
                print ('[DEBUG] ' + str(hex(PEX.OPTIONAL_HEADER.ImageBase + exp.address)) + ' ' + exp.name + ' ' + str(exp.ordinal))
    except Exception as e:
        print ('[-] Unable to process DIRECTORY_ENTRY_EXPORT object: ', e)
        if (POE.logging == True):
            newlogentry = 'Unable to process DIRECTORY_ENTRY_EXPORT object'
            LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)

    try:
        FI.WriteLogFile(output, PEX.dump_info())
        print (colored('[*] PE Dump file has been generated to file here: ', 'green') + colored(output, 'blue', attrs=['bold']))
        if (POE.logging == True):
            newlogentry = 'PE Dump file has been generated to file here: <a href=\"' + output + '\"> Full PE Dump Report </a>'
            LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
    except Exception as e:
        print ('[x] Unable to perform full dump against sample: ', e)
        if (POE.logging == True):
            newlogentry = 'Unable to perform full dump against sample'
            LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
        return -1

    return 0
