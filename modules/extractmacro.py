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
Type: Office - Description: Uses olevba to extract any macro code from a Microsoft Office file.
***END DESCRIPTION***
'''
def POE(POE):

    if (POE.logging == True): 
        LOG = logger() 
    newlogentry = ''
    macro_dump = ''
    macro_output_data = ''
    macro_dump_data = ''
    whois = ''

    if (POE.logging == True):
        newlogentry = 'Module: extractmacro'           
        LOG.WriteStrongLog(POE.logdir, POE.targetfilename, newlogentry)

    FI = fileio()

    print (colored('\r\n[*] Running extractmacro against: ' + POE.target, 'white', attrs=['bold']))

    try:        
        filedata = open(POE.target, 'rb').read()
        vbaparser = VBA_Parser(POE.target, data=filedata)
        if vbaparser.detect_vba_macros():
            print (colored('[-] VBA macros found - Extracting...', 'yellow', attrs=['bold']))
            for (filename, stream_path, vba_filename, vba_code) in vbaparser.extract_macros():
                output = POE.logdir + vba_filename
                macro_dump_data += '-' * 79 + '\n'
                macro_dump_data += 'Filename    : ' + str(filename)
                macro_dump_data += 'OLE stream  : ' + str(stream_path)                
                macro_dump_data += 'VBA filename: ' + str(vba_filename)
                macro_dump_data += '-' * 79 + '\n'
                macro_dump_data += vba_code
                FI.WriteLogFile(output, macro_dump_data)

                try:                     
                    print (colored('[*] Macro ' + vba_filename + ' extracted to: ', 'green') + colored(POE.logdir + vba_filename, 'blue', attrs=['bold']))
                    POE.macros.append(POE.logdir + vba_filename)

                    if (POE.logging == True):
                        newlogentry = 'Macro ' + vba_filename + ' extracted to: <a href=\"' + POE.logdir + vba_filename + '\">' + vba_filename + '</a>'
                    LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
                    if (POE.debug == True):
                        print ('-' * 79)
                        print ('[DEBUG] Filename    : ' + filename)
                        print ('[DEBUG] OLE stream  : ' + stream_path)
                        print ('[DEBUG] VBA filename: ' + vba_filename)
                        print ('-' * 79)
                except Exception as e:                   
                    print (colored('[x] Error - current macro: ' + str(e), 'red', attrs=['bold']))

                if (POE.debug == True):
                    print ('[DEBUG] ' + vba_code)

                macro_dump_data = ''
        else:
            print (colored('[-] No VBA Macros found', 'yellow', attrs=['bold']))
            if (POE.logging == True):
                newlogentry = 'No VBA Macros found'
                LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)     
        vbaparser.close()
    except Exception as e:
        print (colored('[x] Unable to pull macro information: ' + str(e), 'red', attrs=['bold']))
        if (POE.logging == True):
            newlogentry = 'Unable to pull macro information: ' + str(e)
            LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
        return -1

    return 0
