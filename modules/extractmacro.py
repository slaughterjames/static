#python imports
import sys
import os
import subprocess

#third-party imports
from oletools.olevba import VBA_Parser, TYPE_OLE, TYPE_OpenXML, TYPE_Word2003_XML, TYPE_MHTML

#programmer generated imports
from fileclasses import msoclass
from logger import logger
from fileio import fileio

'''
***BEGIN DESCRIPTION***
Extract any macro code from a Microsoft Office file
***END DESCRIPTION***
'''
def POE(logdir, targetfile, logging, debug):

    if (logging == True): 
        LOG = logger()             
    newlogentry = ''
    macro_dump_data = ''

    FI = fileio()

    try:        
        filedata = open(targetfile.filename, 'rb').read()
        vbaparser = VBA_Parser(targetfile.filename, data=filedata)
        if vbaparser.detect_vba_macros():
            print '[*] VBA macros found - Extracting...\n'
            if (logging == True):
                newlogentry = 'VBA macros found - Extracting...'
                LOG.WriteLog(logdir, targetfile.filename, newlogentry)
            for (filename, stream_path, vba_filename, vba_code) in vbaparser.extract_macros():
                macro_dump_data += '-' * 79 + '\n'
                try:
                    macro_dump_data += 'Filename    :' + filename.encode("ascii", "replace") + '\n'
                    macro_dump_data += 'OLE stream  :' + stream_path.encode("ascii", "replace") + '\n'                
                    macro_dump_data += 'VBA filename:' + vba_filename.encode("ascii", "replace") + '\n'
                except Exception, e:
                    print '[x] Current macro - unable to print Filename, OLE stream or VBA filename due to encoding issue (Unicode?): ', e
                macro_dump_data += '-' * 79 + '\n'
                macro_dump_data += vba_code
                FI.WriteLogFile(logdir + vba_filename, macro_dump_data)

                try:                     
                    print '[*] Macro ' + vba_filename.encode("ascii", "replace") + ' extracted to: ' + logdir + vba_filename.encode("ascii", "replace")
                    targetfile.macros.append(logdir + vba_filename.encode("ascii", "replace"))

                    if (logging == True):
                        newlogentry = 'Macro ' + vba_filename.encode("ascii", "replace") + ' extracted to: <a href=\"' + logdir + vba_filename.encode("ascii", "replace") + '\">' + vba_filename.encode("ascii", "replace") + '</a>'
                    LOG.WriteLog(logdir, targetfile.filename, newlogentry)
                    if (debug == True):
                        print '-'*79
                        print 'Filename    :', filename.encode("ascii", "replace")
                        print 'OLE stream  :', stream_path.encode("ascii", "replace")
                        print 'VBA filename:', vba_filename.encode("utf-8", "ignore")
                        print '-'*79
                except Exception, e:
                    print '[x] Current macro - unable print Filename, OLE stream or VBA filename due to encoding issue: (Unicode?)', e

                if (debug == True):
                    print vba_code

                macro_dump_data = ''
            print 'Macro List'
            for mlist in targetfile.macros:
                print mlist
        else:
            print '[x] No VBA Macros found' 
            if (logging == True):
                newlogentry = 'No VBA Macros found'
                LOG.WriteLog(logdir, targetfile.filename, newlogentry)     

        vbaparser.close()
    except Exception, e:
        print '[x] Unable to pull macro information: ', e 
        if (logging == True):
            newlogentry = 'Unable to pull macro information: ', e
            LOG.WriteLog(logdir, targetfile.filename, newlogentry) 
        return -1
