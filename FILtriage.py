'''
Static v0.1 - Copyright 2016 James Slaughter,
This file is part of Static v0.1.

Static v0.1 is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Static v0.1 is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Static v0.1.  If not, see <http://www.gnu.org/licenses/>.
'''

'''
FILtriage.py - This file is responsible for obtaining basic information about a target
               file including verifying the file type and gather hashes
'''

#python imports
import sys
import os
import subprocess

#programmer generated imports
from logger import logger
from fileclasses import peclass, pdfclass, msoclass, elfclass

'''
filetriage
Class: This file is responsible for obtaining basic information about a target
       file including verifying the file type and gather hashes
'''
class filetriage:
    '''
    Constructor
    '''
    def __init__(self):
        fn = ''

    '''
    MD5()
    Function: - Get the MD5 sum of the uploaded sample 
    '''     
    def MD5(self, target, logdir, logging, LOG, debug):
        temp = ''
        strpos = 0
        if (logging == True): 
            LOG = logger() 
        newlogentry = ''

        #Run the MD5 sum to pull the hash from the target file
        subproc = subprocess.Popen('md5sum ' + target, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)     
        for md5data in subproc.stdout.readlines():
            temp = md5data
    
        strpos = temp.find(' ')

        MD5 = temp[0:strpos]
        print '[*] MD5 hash of file ' + target + ': ' + str(MD5) 

        if (logging == True):
            newlogentry = 'MD5 hash of file ' + target + ': <strong>' + str(MD5) + '</strong>'
            LOG.WriteLog(logdir, target, newlogentry)
       
        return MD5    

    '''
    SHA256()
    Function: - Get the SHA256 sum of the uploaded sample
    '''
    def SHA256(self, target, logdir, logging, LOG, debug):
        temp = ''
        strpos = 0
        newlogentry = ''

        #Run the sha256 sum to pull the hash from the target file
        subproc = subprocess.Popen('sha256sum '+ target, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for sha256data in subproc.stdout.readlines():
            temp = sha256data

        strpos = temp.find(' ')

        SHA256 = temp[0:strpos]
        print '[*] SHA256 hash of file ' + target + ': ' + str(SHA256) 

        if (logging == True):
            newlogentry = 'SHA256 hash of file ' + target + ': <strong>' + str(SHA256) + '</strong>'
            LOG.WriteLog(logdir, target, newlogentry)
            newlogentry = 'The live VirusTotal Data can be found here: <a href=\"''https://www.virustotal.com/en/file/' + str(SHA256) + '/analysis/' '\"> VirusTotal Report </a>'
            LOG.WriteLog(logdir, target, newlogentry)        

        print '[*] If a VirusTotal record exists, it will be located here: https://www.virustotal.com/en/file/' + str(SHA256) + '/analysis/'

        return SHA256

    '''
    filetype()
    Function: - verify the filetype of the sample
    '''
    def filetype(self, target, logdir, logging, LOG, debug):
        temp = ''
        intLen = 0
        strpos = 0
        newlogentry = ''

        #Run the file command to pull the header data from the target
        subproc = subprocess.Popen('file '+ target, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for filedata in subproc.stdout.readlines():
            temp = filedata

        intLen = len(temp)
        strpos = temp.find(':')

        header = temp[strpos+1:intLen]
        print '[*] Fileheader: ' + filedata 

        if (logging == True):
            newlogentry = 'Fileheader for ' + target + ': <strong>' + filedata + '</strong>'
            LOG.WriteLog(logdir, target, newlogentry)

        return header    

    '''
    Triage()
    Function: - Function caller
    '''
    def Triage(self, FIL, logging, logdir,  debug):

        if (logging == True): 
            LOG = logger()
        else:
            LOG = ''

        FIL.MD5 = self.MD5(FIL.filename, logdir, logging, LOG, debug)
        FIL.SHA256 = self.SHA256(FIL.filename, logdir, logging, LOG, debug)
        FIL.header = self.filetype(FIL.filename, logdir, logging, LOG, debug)

        return FIL
