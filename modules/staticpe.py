#python imports
import sys
import os
import subprocess

#third-party imports
import pefile
import peutils

#programmer generated imports
from peclass import peclass
from logger import logger
from fileio import fileio

'''
***BEGIN DESCRIPTION***
Uses PEUtils to get the particulars on the submitted sample to give a jump start on reverse engineering
***END DESCRIPTION***
'''
def POE(logdir, target, logging, debug):
            
    newlogentry = ''
    full_dump = ''
    matches = ''
    output = logdir + 'FullDump.txt'
    signaturedb = '/etc/static/UserDB.txt'
    if (logging == True): 
        LOG = logger()

    FI = fileio()
    SIG = peutils.SignatureDatabase(signaturedb)
    PEX = pefile.PE(target.filename)
 
    if (logging == True):
        newlogentry = 'PEiD Signature (...if signature database present):'
        LOG.WriteLog(logdir, target.filename, newlogentry)   

    if (signaturedb != ''):
        matches = SIG.match_all(PEX, ep_only = True)
  
        print '[*] Signature Matches: ' + str(matches)

        if (logging == True):
            newlogentry = 'Signature: ' + '<strong>' + str(matches) + '</strong>'
            LOG.WriteLog(logdir, target.filename, newlogentry)

            newlogentry = 'Sample Attribute Sections:'
            LOG.WriteLog(logdir, target.filename, newlogentry)

    for section in PEX.sections:
        if (debug == True):
            print '[DEBUG] ' + section.Name + ' Virtual Address: ' + str(hex(section.VirtualAddress)) + ' Virtual Size: ' + str(hex(section.Misc_VirtualSize)) + ' Raw Data Size: ' +  str(section.SizeOfRawData) 
  
    try:
        for entry in PEX.DIRECTORY_ENTRY_IMPORT: 
            for imp in entry.imports:
                if (debug == True):
                    print '[DEBUG] imp address and name: ' + str(hex(imp.address)) +  str(imp.name)
    except Exception, e:
        print '[-] Unable to process DIRECTORY_ENTRY_IMPORT object: ', e 
        if (logging == True):
            newlogentry = 'Unable to process DIRECTORY_ENTRY_IMPORT object'
            LOG.WriteLog(logdir, target.filename, newlogentry)
  
    try:
        for exp in PEX.DIRECTORY_ENTRY_EXPORT.symbols:
            if (debug == True):
                print '[DEBUG] ' + str(hex(PEX.OPTIONAL_HEADER.ImageBase + exp.address)) + ' ' + exp.name + ' ' + str(exp.ordinal)
    except Exception, e:
        print '[-] Unable to process DIRECTORY_ENTRY_EXPORT object: ', e
        if (logging == True):
            newlogentry = 'Unable to process DIRECTORY_ENTRY_EXPORT object'
            LOG.WriteLog(logdir, target.filename, newlogentry)

    try:
        FI.WriteLogFile(output, PEX.dump_info())
        print '[*] Dump file has been generated to file here: ' + output
        if (logging == True):
            newlogentry = 'Dump file has been generated to file here: <a href=\"' + output + '\"> Full Dump Report </a>'
            LOG.WriteLog(logdir, target.filename, newlogentry)
    except Exception, e:
        print '[x] Unable to perform full dump against sample: ', e
        if (logging == True):
            newlogentry = 'Unable to perform full dump against uploaded file'
            LOG.WriteLog(logdir, target.filename, newlogentry)
        return -1

    return 0
