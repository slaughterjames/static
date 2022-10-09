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
Type: PE - Description: Uses PEUtils to generate a PEID sig for the target.
***END DESCRIPTION***
'''
def POE(POE):
            
    newlogentry = ''
    enum_output_data = ''
    length = 512
    signaturedb = '/opt/static/userdb.txt'
    #signature = ''
    output = POE.logdir + 'PEID_Sig.txt'
    if (POE.logging == True): 
        LOG = logger()

    FI = fileio()
    PEX = pefile.PE(POE.target)
    SIG = peutils.SignatureDatabase('https://raw.githubusercontent.com/guelfoweb/peframe/5beta/peframe/signatures/userdb.txt')
    #SIG = peutils.SignatureDatabase(signaturedb)

    if (POE.logging == True):
        newlogentry = 'Module: peid_sig'           
        LOG.WriteStrongLog(POE.logdir, POE.targetfilename, newlogentry)

    print (colored('\r\n[*] Running peid_sig against: ' + POE.target, 'white', attrs=['bold']))
    print ('Got here')
    signature = peutils.generate_ep_signature(POE.target, POE.targetfilename, length)
    print ('Got here II')
    enum_output_data += 'PEiD Signature: ' + str(signature) + '\n'
    print ('Got here III')
    print ('[*] PEiD Signature: ' + str(signature) + '\n')
    newlogentry = 'PEiD Signature: ' + str(signature)
    LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)

    try:        
        FI.WriteLogFile(output, enum_output_data)
        print ('[*] PEiD signature had been written to file here: ' + output + '\n')
        if (POE.logging == True):
            newlogentry = 'PEiD signature has been generated to file here: <a href=\"' + output + '\"> PEiD Signature </a>'
            LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
    except:
        print ('[x] Unable to write quickenum data to file')
        if (POE.logging == True):
            newlogentry = 'Unable to write PEiD signature data to file'
            LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
        return -1

    return 0
