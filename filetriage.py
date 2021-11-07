'''
Static v0.2 - Copyright 2021 James Slaughter,
This file is part of Static v0.2.

Static v0.2 is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Static v0.2 is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Static v0.2.  If not, see <http://www.gnu.org/licenses/>.
'''

'''
FILtriage.py - This file is responsible for obtaining basic information about a target
               file including verifying the file type and gather hashes
'''

#python imports
import sys
import os
import subprocess
import hashlib
from termcolor import colored

#programmer generated imports
from logger import logger
from targetclass import targetclass
from fileio import fileio

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
    filesize()
    Function: - verify the size of the sample
    '''
    def filesize(self, target, logging, logdir,  debug):
        temp = ''
        intLen = 0
        strpos = 0
        newlogentry = ''
        
        filesize = str(os.path.getsize(target.target))

        return filesize

    '''
    fileextension()
    Function: - verify the file extension of the sample
    '''
    def fileextension(self, target, logging, logdir,  debug):
        temp = ''
        intLen = 0
        strpos = 0
        newlogentry = ''

        try:
            extension = target.target.rsplit('.',1)[1]
        except:
            extension = 'none' 

        return extension

    '''
    officeunzip()
    Function: - Unzip an MS Office 2007+ sample
    '''
    def officeunzip(self, target, logging, logdir, LOG, nolinksummary, debug):
        temp = ''
        intLen = 0
        strpos = 0
        output = logdir + 'unzip'
        newlogentry = ''

        #Run the unzip command to decompress the target
        subproc = subprocess.Popen('unzip '+ target.target + ' -d ' + output, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for filedata in subproc.stdout.readlines():
            temp = str(filedata)
            if (debug == True):
                print ('temp: ' + temp)

        print (colored('[*] File has been unzipped to: ', 'green') + colored(output, 'blue', attrs=['bold']))
        if ((logging == True) and (nolinksummary == False)):
            newlogentry = 'File has been unzipped to: <a href=\"' + output + '\"> Unzip </a>'           
            LOG.WriteSubLog(logdir, target.targetfilename, newlogentry)

        return 0


    '''
    filetype()
    Function: - verify the filetype of the sample
    '''
    def filetype(self, target, logging, logdir,  debug):
        temp = ''
        intLen = 0
        strpos = 0
        newlogentry = ''

        #Run the file command to pull the header data from the target
        subproc = subprocess.Popen('file '+ target.target, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for filedata in subproc.stdout.readlines():
            temp = str(filedata)
            if (debug == True):
                print ('temp: ' + temp)

        intLen = len(temp)
        strpos = temp.find(':')

        header = temp[strpos+1:intLen]

        return header

    '''
    exif()
    Function: - Pull the Exif metadata of the file
    '''
    def exif(self, target, logging, logdir, LOG, nolinksummary, debug):

        output = logdir + 'exif.txt'
        exifdata = ''
        exif_data = ''
        exif_output_data = ''

        FI = fileio()

        subproc = subprocess.Popen('exiftool ' + target.target + ' > ' + output, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for exifdata in subproc.stdout.readlines():        
            if (debug == True):
                print ('Exif: ' + exifdata + '\n')

        print (colored('[*] Exif data had been written to file here: ', 'green') + colored(output, 'blue', attrs=['bold']))
        if ((logging == True) and (nolinksummary == False)):
            newlogentry = 'Exif data has been generated to file here: <a href=\"' + output + '\"> Exif </a>'           
            LOG.WriteSubLog(logdir, target.targetfilename, newlogentry)

        try:
            #Open the file we just downloaded
            print ('[-] Reading Exif file: ' + output.strip())            
            FI.ReadFile(output.strip())
        except Exception as e:
            print (colored('[x] An error has occurred: ' + str(e), 'red', attrs=['bold']))
            return -1

        for exif_data in FI.fileobject:
            exif_output_data += str(exif_data).strip('b\'\\n') + '\n'
            if (debug == True):
                print (exif_output_data)


            if('File Type' in exif_data):
                print (colored('[*] ' + exif_data, 'green',attrs=['bold']))
                if (logging == True):
                    newlogentry = exif_data
                    LOG.WriteSubLog(logdir, target.targetfilename, newlogentry)
            elif('Software' in exif_data):
                print (colored('[*] ' + exif_data, 'green',attrs=['bold']))
                if (logging == True):
                    newlogentry = exif_data
                    LOG.WriteSubLog(logdir, target.targetfilename, newlogentry)        
            elif('MIME Type' in exif_data):
                print (colored('[*] ' + exif_data, 'green',attrs=['bold']))
                if (logging == True):
                    newlogentry = exif_data
                    LOG.WriteSubLog(logdir, target.targetfilename, newlogentry)
            elif ('Software:' in exif_data):
                print (colored('[*] ' + exif_data, 'green',attrs=['bold']))
                if (logging == True):
                    newlogentry = exif_data
                    LOG.WriteSubLog(logdir, target.targetfilename, newlogentry)
            elif ('Comp Obj User Type' in exif_data):
                print (colored('[*] ' + exif_data, 'green',attrs=['bold']))
                if (logging == True):
                    newlogentry = exif_data
                    LOG.WriteSubLog(logdir, target.targetfilename, newlogentry)               

        return 0

    '''
    strings()
    Function: - Run the strings command on the file
    '''
    def strings(self, target, logging, logdir, LOG, nolinksummary, debug):

        output = logdir + 'strings.txt'
        stringsdata = ''
        strings_data = ''
        strings_output_data = ''

        FI = fileio()

        subproc = subprocess.Popen('strings -a ' + target.target + ' > ' + output, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for stringsdata in subproc.stdout.readlines():        
            if (debug == True):
                print ('Strings: ' + stringsdata + '\n')

        print (colored('[*] Strings data had been written to file here: ', 'green') + colored(output, 'blue', attrs=['bold']))
        print ('')
        if ((logging == True) and (nolinksummary == False)):
            newlogentry = 'Strings data has been generated to file here: <a href=\"' + output + '\"> Strings </a>'           
            LOG.WriteSubLog(logdir, target.targetfilename, newlogentry)


        return 0
    
    '''
    triage()
    Function: - Main function of this class.  Calls all others.
    '''
    def triage(self, target, logging, logdir, nolinksummary, debug):

        if (logging == True): 
            LOG = logger()
        newlogentry = ''

        FI = fileio()

        if (logging == True):
            newlogentry = 'Module: triage'           
            LOG.WriteStrongLog(logdir, target.targetfilename, newlogentry)

        print (colored('\r\n[*] Beginning file triage... ', 'white', attrs=['bold']))

        target.filesize = self.filesize(target, logging, logdir,  debug)
        print ('[*] Filesize is: ' + target.filesize + ' bytes.')

        target.MD5 = hashlib.md5(open(target.target,'rb').read()).hexdigest()
        print ('[*] MD5 hash of file ' + target.filename + ': ' + target.MD5)

        target.SHA1 = hashlib.sha1(open(target.target,'rb').read()).hexdigest()
        print ('[*] SHA1 hash of file ' + target.filename + ': ' + target.SHA1)

        target.SHA256 = hashlib.sha256(open(target.target,'rb').read()).hexdigest()
        print ('[*] SHA256 hash of file ' + target.filename + ': ' + target.SHA256)

        print ('[*] If a VirusTotal record exists, it will be located here: https://www.virustotal.com/en/file/' + str(target.SHA256) + '/analysis/') 

        if (logging == True):
            newlogentry = 'Size of file ' + target.target + ': ' + target.filesize + ' bytes.'          
            LOG.WriteSubLog(logdir, target.targetfilename, newlogentry)
            newlogentry = 'MD5 hash of file ' + target.target + ': ' + target.MD5          
            LOG.WriteSubLog(logdir, target.targetfilename, newlogentry)
            newlogentry = 'SHA1 hash of file ' + target.target + ': ' + target.SHA1          
            LOG.WriteSubLog(logdir, target.targetfilename, newlogentry)
            newlogentry = 'SHA256 hash of file ' + target.target + ': ' + target.SHA256          
            LOG.WriteSubLog(logdir, target.targetfilename, newlogentry)
            newlogentry = 'If a VirusTotal record exists, it will be located here: https://www.virustotal.com/en/file/' + str(target.SHA256) + '/analysis/'
            LOG.WriteSubLog(logdir, target.targetfilename, newlogentry)

        target.extension = self.fileextension(target, logging, logdir,  debug)

        if (target.extension == 'none'):
            print (colored('[-] File has no extension...', 'yellow', attrs=['bold']))
        else:
            print ('[*] File extension: ' + target.extension)

        if ((target.extension == 'docm') or (target.extension == 'docx') or (target.extension == 'dotm') or (target.extension == 'dotx') or (target.extension == 'potm') or (target.extension == 'potx') or (target.extension == 'ppam') or (target.extension == 'ppsm') or (target.extension == 'ppsx') or (target.extension == 'pptm') or (target.extension == 'pptx') or (target.extension == 'xlam') or (target.extension == 'xlsb') or (target.extension == 'xlsm') or (target.extension == 'xlsx') or (target.extension == 'xltm') or (target.extension == 'xltx')):
            print ('[*] File is MS Office 2007+.  Unzipping...')
            self.officeunzip(target, logging, logdir, LOG, nolinksummary, debug)

        target.header = self.filetype(target, logging, logdir,  debug)

        print ('[*] File type: ' + target.target + ': ' + target.header)
        if (logging == True):
            newlogentry = 'File type: ' + target.target + ': ' + target.header        
            LOG.WriteSubLog(logdir, target.targetfilename, newlogentry)

        
        self.exif(target, logging, logdir, LOG, nolinksummary, debug)

        self.strings(target, logging, logdir, LOG, nolinksummary, debug)
               
        return target
