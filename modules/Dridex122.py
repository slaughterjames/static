#python imports
import sys
import os
import subprocess
import base64

#third-party imports

#programmer generated imports
from msoclass import msoclass
from logger import logger
from fileio import fileio

'''
***BEGIN DESCRIPTION***
Analyzes known Dridex affiliate 12X faux MS-Word e-mail attachments
***END DESCRIPTION***
'''
def POE(logdir, target, logging, debug):

    if (logging == True): 
        LOG = logger()             
    newlogentry = ''
    macro_dump_data = ''
    output = logdir
    oledump = '/opt/remnux-didier/oledump.py'
    B64 = ''
    B64_output = logdir + 'base64.bin'
    oledump_data = ''
    oledump_output_data = ''
    intLen = 0
    i = 0
    j = 0
    streamnum = ''
    result = ''
    flag = 0
    count = 0

    FI = fileio()

    print '[*] Searching file for parameters matching the Dridex 122 affiliate in: ' + target.filename
    if (logging == True):
        newlogentry = 'Searching file for parameters matching the Dridex Dridex 122 affiliate in: ' + target.filename
        LOG.WriteLog(logdir, target.filename, newlogentry)

        FI.ReadFile(target.filename)
        
        for line in FI.fileobject:
            if (flag == 1):                   
                if (line.find('Content-Type: application/x-mso') != -1):
                    print '[*] Skipping a line'
                    flag = 2
                if ((count > 0) and (flag == 1)):
                    flag = 0  
            if (line.find('Content-Transfer-Encoding: base64') != -1):
                print '[*] Found a Base64 block'                             
                flag = 1
                count += 1            
            if (flag == 2):
                if (line.find('------=_NextPart') != -1):
                    flag = 3 
                else:                    
                    if (line.find('Content-Type: application/x-mso') == -1):
                        if (debug == True):
                            print line
                        B64 += line
            
                               
    if (flag == 0):
        print '[-] Base64 section not found.  File does not match the parameters for the Dridex 122 affilliate.'
    else:
        print '[*] Decoding base64 data'
        data = base64.b64decode(B64)      
  
        try:        
            FI.WriteLogFile(B64_output, data)
            print '[*] Binary output of the decoded base64 block written to file here: ' + B64_output
            if (logging == True):
                newlogentry = 'Binary output of the decoded base64 block generated to file here: <a href=\"' + B64_output + '\"> Base64 Output </a>'
                LOG.WriteLog(logdir, target.filename, newlogentry)
        except:
            print '[x] Unable to write binary output of the decoded base64 block to file' 
            if (logging == True):
                newlogentry = 'Unable to write binary output of the decoded base64 block to file'
                LOG.WriteLog(logdir, target.filename, newlogentry)
            return -1

        print '[*] Running OLEDump on the Base64 block'

        subproc = subprocess.Popen(oledump + ' ' + B64_output, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if (debug == True):
            print '[DEBUG] OLEDump:'
            for oledump_data_debug in subproc.stdout.readlines():
                print oledump_data_debug      

        subproc = subprocess.Popen(oledump + ' ' + B64_output, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for oledump_data in subproc.stdout.readlines():
            if (oledump_data.find(': m') != -1):
                i = oledump_data.find(': m')
            if (oledump_data.find(': M') != -1):
                i = oledump_data.find(': M')
            if (i != 0):
                streamnum =  oledump_data[0:i].strip()
                subproc = subprocess.Popen(oledump + ' -s ' + streamnum + ' -v ' + B64_output + ' > ' + output + 'stream' + streamnum + '.txt', shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                print '[*] Stream output written to file here: ' + output + 'stream' + streamnum + '.txt'
                if (logging == True):
                    newlogentry = 'Stream output written to file here: <a href=\"' + output + '\"> Stream ' + streamnum + 'Output </a>'
                    LOG.WriteLog(logdir, target.filename, newlogentry)        
                for stream_data in subproc.stdout.readlines():
                    if (debug == True):
                        print stream_data
                i = 0                                  
            else:
                j = oledump_data.find(':')
                streamnum = oledump_data[0:j].strip()
                subproc = subprocess.Popen(oledump + ' -s ' + streamnum + ' ' + B64_output  + ' > ' + output + 'stream' + streamnum + '.txt', shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                print '[*] Stream output written to file here: ' + output + 'stream' + streamnum + '.txt'
                if (logging == True):
                    newlogentry = 'Stream output written to file here: <a href=\"' + output + '\"> Stream ' + streamnum + 'Output </a>'
                    LOG.WriteLog(logdir, target.filename, newlogentry)
                for stream_data in subproc.stdout.readlines():
                    if (debug == True):
                        print stream_data
                j = 0

            oledump_output_data += oledump_data
                                                                                   
    return 0
