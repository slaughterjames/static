#python imports
import sys
import os
import subprocess

#third-party imports

#programmer generated imports
from fileclasses import msoclass
from logger import logger
from fileio import fileio

'''
***BEGIN DESCRIPTION***
Analyzes known Dridex affiliate 22X Macro based MS-Word and MS-Excel e-mail attachments. Use the file Dridex.txt to add a date and decode algorithm to handle multiple samples without having to create a new module for each campaign.
***END DESCRIPTION***
'''
def POE(logdir, target, logging, debug):

    if (logging == True): 
        LOG = logger()             
    newlogentry = ''
    macro_dump_data = ''
    output = logdir
    date = ''
    algo = ''
    intLen = 0
    i = 0
    comma = 0
    arrayline = ''
    arraylist = []
    result = ''
    count = 0

    FI = fileio()
    FI2 = fileio()

    FI.ReadFile('/opt/static/modules/Dridex220.txt')

    if (len(target.macros) == 0):
        print '[x] Macros are not present in this file -OR- extractmacros did not run first.'
        return 0 

    for line in FI.fileobject:
        intLen = len(line)
        comma = line.find(',')  
        date = line[0:comma]
        algo = line[comma+1:intLen]
        
        print '\n[*] Searching macros for parameters matching the Dridex 220 campaign from ' + date + ' in: ' + target.filename
        if (logging == True):
            newlogentry = 'Searching macros for parameters matching the Dridex 220 campaign from ' + date + ' in: ' + target.filename
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

            FI2.ReadFile(macro_name)
        
            for macroline in FI2.fileobject:            
                intLen = len(macroline)
                i = macroline.find('= Array(')
                if (i != -1):
                    arrayline = macroline[i+8:intLen].strip()
                    arrayline = arrayline[:-1]
                    if (logging == True):
                        print '[*] Array: ' + str(arrayline)
                    arraylist = arrayline.split(",")
                    elements = len(arraylist) - 1
                    if (logging == True):
                        print '[*] Number of elements in array: ' + str(elements)
                    if (elements < 10):
                        if (logging == True): 
                            print '[-] Array too small to produce a URL.  Skipping...'
                    else: 
                        try: 
                            for arrayline in arraylist:
                                value = arrayline + '-' + algo
                                value = eval(value)
                                if (value < 257):
                                    result += chr(value)
                                    if (logging == True):
                                        print 'result: ' + str(result)
                                    value = 0                    
                                    count = count + 1 

                            j = result.find('http')
                            if (j != -1):
                                print '\033[31;1m[*] Dridex download location: ' + result + '\033[0m'
                                if (logging == True):
                                    newlogentry = 'Dridex download location: ' + result
                                    LOG.WriteLog(logdir, target.filename, newlogentry)
                                result = ''                                    
                            else:
                                print '[-] No Dridex download URL available.'
                            result = ''
                        except Exception, e:
                            print '[x] Unable to process array'                                                                      
                                                                             
    return 0
