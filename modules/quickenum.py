#python imports
#standard widely used classes, add  or remove as needed
import sys
import os
import subprocess
import datetime
import time

#third-party imports
import pefile
import peutils

#programmer generated imports
from peclass import peclass
from logger import logger
from fileio import fileio

'''
***BEGIN DESCRIPTION***
Quickly ennumerates the different sections of the PE file target and lists things like the compile time if available.
***END DESCRIPTION***
'''
def POE(logdir, target, logging, debug):
    newlogentry = ''
    enum_output_data = ''
    length = 512
    signaturedb = '/etc/static/UserDB.txt'
    signature = ''
    output = logdir + 'Quickenum.txt'

    if (logging == True): 
        LOG = logger()
        newlogentry = 'Running quickenum against: <strong>' + target.filename + '</strong>'
        LOG.WriteLog(logdir, target.filename, newlogentry)

    FI = fileio()
    PEX = pefile.PE(target.filename)
    SIG = peutils.SignatureDatabase(signaturedb)

    enum_output_data += '-' * 79 + '\n'
    enum_output_data += 'PE sections for sample: ' + target.filename + '\n'
    enum_output_data += '-' * 79 + '\n'
    enum_output_data += '\n'
    enum_output_data += 'File compile time: ' + str(datetime.datetime.fromtimestamp(PEX.FILE_HEADER.TimeDateStamp)) + '\n'
    enum_output_data += '\n'
    print '[*] File compile time: ' + str(datetime.datetime.fromtimestamp(PEX.FILE_HEADER.TimeDateStamp))
    if (logging == True):
        newlogentry = 'File compile time: ' + '<strong>' + str(datetime.datetime.fromtimestamp(PEX.FILE_HEADER.TimeDateStamp)) + '</strong>'
        LOG.WriteLog(logdir, target.filename, newlogentry)

    signature = SIG.generate_ep_signature(PEX, target.filename, length)
    enum_output_data += 'PEiD Signature: ' + str(signature) + '\n'
    print '[*] PEiD Signature: ' + str(signature) + '\n'        

    for section in PEX.sections:
        enum_output_data += 'Section Name: ' + section.Name[:5] + '\n'
        print '[*] Section Name: ' + section.Name
        enum_output_data += 'Virtual Address: ' + str(hex(section.VirtualAddress)) + '\n'
        print '    Virtual Address: ' + str(hex(section.VirtualAddress)) 
        enum_output_data += 'Virtual Size: ' + str(hex(section.Misc_VirtualSize)) + '\n' 
        print '    Virtual Size: ' + str(hex(section.Misc_VirtualSize)) 
        enum_output_data += 'Raw Data Size: ' +  str(section.SizeOfRawData) + '\n'
        print '    Raw Data Size: ' +  str(section.SizeOfRawData) + '\n'
        enum_output_data += '\n'

    try:        
        FI.WriteLogFile(output, enum_output_data)
        print '[*] Quickenum data had been written to file here: ' + output + '\n'
        if (logging == True):
            newlogentry = 'Quickenum file has been generated to file here: <a href=\"' + output + '\"> Enumsections Output </a>'
            LOG.WriteLog(logdir, target.filename, newlogentry)
    except:
        print '[x] Unable to write quickenum data to file' 
        if (logging == True):
            newlogentry = 'Unable to write quickenum data to file'
            LOG.WriteLog(logdir, target.filename, newlogentry)
        return -1
 
    return 0
