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
PETriage.py - This file is responsible for the parsing of input data from the command line
               from a user and then populating the appropriate values for use elsewhere in 
               the code
'''

#python imports
import sys
import os
import subprocess

#programmer generated imports
from logger import logger
from peclass import peclass

'''
argparser
Class: This class is responsible for the parsing of input data from the command line
from a user and then populating the appropriate values for use elsewhere in the code
'''
class petriage:
    '''
    Constructor
    '''
    def __init__(self):
        fn = ''

    '''
    MD5()
    Function: - Get the MD5 sum of the uploaded sample 
    '''     
    def MD5(self, target, debug):
        temp = ''
        strpos = 0
        newlogentry = ''

        #newlogentry = 'MD5 hash of uploaded sample file: <strong>' + AP.filename + '</strong>'
        #LOG.WriteLog(AP.filename, newlogentry)
        #newlogentry = ''
        subproc = subprocess.Popen('md5sum ' + target, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)     
        for md5data in subproc.stdout.readlines():
            temp = md5data
    
        strpos = temp.find(' ')

        MD5 = temp[0:strpos]
        print '[*] MD5 hash of file ' + target + ': ' + str(MD5) 

        #newlogentry = '<strong>' + AP.MD5 + '</strong>'
        #LOG.WriteLog(AP.filename, newlogentry)
        #newlogentry = ''
       
        return MD5    

    '''
    SHA256()
    Function: - Get the SHA256 sum of the uploaded sample
    '''
    def SHA256(self, target, debug):
        temp = ''
        strpos = 0
        newlogentry = ''

        #newlogentry = 'SHA256 hash of uploaded sample file: <strong>' + AP.filename + '</strong>'
        #LOG.WriteLog(AP.filename, newlogentry)
        #newlogentry = ''
        subproc = subprocess.Popen('sha256sum '+ target, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for sha256data in subproc.stdout.readlines():
            temp = sha256data

        strpos = temp.find(' ')

        SHA256 = temp[0:strpos]
        print '[*] SHA256 hash of file ' + target + ': ' + str(SHA256) 

        #newlogentry = '<strong>' + AP.SHA256 + '</strong>'
        #LOG.WriteLog(AP.filename, newlogentry)
        #newlogentry = ''

        return SHA256

    '''
    filetype()
    Function: - verify the filetype of the sample
    '''
    def filetype(self, target, debug):
        temp = ''
        intLen = 0
        strpos = 0
        newlogentry = ''

        #newlogentry = 'SHA256 hash of uploaded sample file: <strong>' + AP.filename + '</strong>'
        #LOG.WriteLog(AP.filename, newlogentry)
        #newlogentry = ''
        subproc = subprocess.Popen('file '+ target, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for filedata in subproc.stdout.readlines():
            temp = filedata

        intLen = len(temp)
        strpos = temp.find(':')

        header = temp[strpos+1:intLen]
        print '[*] ' + filedata 

        #newlogentry = '<strong>' + AP.SHA256 + '</strong>'
        #LOG.WriteLog(AP.filename, newlogentry)
        #newlogentry = ''

        return header    

    '''
    Triage()
    Function: - Get the SHA256 sum of the uploaded sample
    '''
    def Triage(self, PEC, debug):

        PEC.MD5 = self.MD5(PEC.filename, debug)
        PEC.SHA256 = self.SHA256(PEC.filename, debug)
        PEC.header = self.filetype(PEC.filename, debug)

        return PEC 
