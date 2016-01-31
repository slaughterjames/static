#python imports
import sys
import os
import subprocess
import re
import string
import unicodedata
from unidecode import unidecode

#third-party imports

#programmer generated imports
from msoclass import msoclass
from logger import logger
from fileio import fileio

'''
Template()
Function: - Does what you want
'''
def POE(logdir, target, logging, debug):

    if (logging == True): 
        LOG = logger()             
    newlogentry = ''
    macro_dump_data = ''
    output = logdir
    intLen = 0
    i = 0
    arrayline = ''
    arraylist = []
    result = ''
    count = 0
    r = re.compile('Chr\$\((\S+) \+ (\S+)\)')
    r2 = re.compile('Chr\((\S+) \+ (\S+)\)')

    FI = fileio()

    print '[*] Searching macros for Chr() commands in: ' + target.filename
    if (logging == True):
        newlogentry = 'Searching macros for Chr() commands in: ' + target.filename
        LOG.WriteLog(logdir, target.filename, newlogentry)

    for macro_name in target.macros:
        try:    
            print '[*] Checking macro: ' + macro_name
            if (logging == True):
                newlogentry = 'Checking macro: ' + macro_name
                LOG.WriteLog(logdir, target.filename, newlogentry)
               
        except Exception, e:
            print '[x] Unable print macro name due to encoding issue: (Unicode?)'
            if (logging == True):
                newlogentry = 'Unable print macro name due to encoding issue: (Unicode?)'
                LOG.WriteLog(logdir, target.filename, newlogentry)

        print 'reading macro'

        FI.Read(macro_name)
        i = re.findall(r, FI.fileobject)
        cmd = ''
        cmd_uni = ''
        for match in i:
            if (debug == True):
                print '[DEBUG] Match: ' + str(match[0]).strip('Chr\$\'\(\)') + ' ' + str(match[1]).strip('Chr\$\'\(\)')
            cmd = cmd + chr(int(str(match[0]).strip('Chr\$\'\(\)'))) + chr(int(str(match[1]).strip('Chr\$\'\(\)')))
            cmd_uni = cmd_uni + unichr(int(str(match[0]).strip('Chr\$\'\(\)'))) + unichr(int(str(match[1]).strip('Chr\$\'\(\)')))

        j = re.findall(r2, FI.fileobject)
        for match in j:
            if (debug == True):
                print '[*] Match: ' + str(match[0]).strip('Chr\$\'\(\)') + ' ' + str(match[1]).strip('Chr\$\'\(\)')
            cmd = cmd + chr(int(str(match[0]).strip('Chr\$\'\(\)'))) + chr(int(str(match[1]).strip('Chr\$\'\(\)')))
            cmd_uni = cmd_uni + unichr(int(str(match[0]).strip('Chr\$\'\(\)'))) + unichr(int(str(match[1]).strip('Chr\$\'\(\)')))

    if (cmd == ''):
        print '[-] No Chr() commands found'
    else:
        print '[*] Command: ' + str(cmd)
        print '[*] Command in Unicode: ' + unicodedata.normalize('NFKC', cmd_uni).encode('UTF-8', 'ignore')
                                                     
    return 0
