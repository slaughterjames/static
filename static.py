#!/usr/bin/python

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
static.py - This is the main file of the program and is the jumping off point
into the rest of the code
'''

#python imports
import sys
import os
import subprocess

#third-party imports
import pefile
import peutils

#programmer generated imports
from controller import controller
from fileclasses import peclass, pdfclass, msoclass, elfclass
from FILtriage import filetriage
from logger import logger
from fileio import fileio

'''
Usage()
Function: Display the usage parameters when called
'''
def Usage():
    print 'Usage: [required] --target --type --modules [all|specific] --force --output -- debug --listmodules --help'
    print 'Example: /opt/static/static.py --target 123.exe --type pe --modules all --output /your/directory --debug'
    print 'Required Arguments:'
    print '--target - file that will be analyzed'
    print '--type - pe, elf, office, pdf'
    print '--modules - all or specific'
    print 'Optional Arguments:'
    print '--force - force analysis type even if the header details don\'t match'
    print '--output - choose where you wish the output to be directed'
    print '--listmodules - prints a list of available modules and their descriptions'
    print '--debug - prints verbose output to the screen '
    print '--help - You\'re looking at it!'
    sys.exit(-1)
    

'''
ConfRead()
Function: - Reads in the static.conf config file
'''
def ConfRead():
        
    ret = 0
    intLen = 0
    FConf = fileio()
    try:
        #Conf file hardcoded here
    	FConf.ReadFile('/opt/static/static.conf')
    except:
        print '[x] Unable to read configuration file'
        return -1
    
    for line in FConf.fileobject:
        intLen = len(line)            
        if (CON.debug == True):
            print line                    
        if (line.find('logging') != -1):
            CON.logger = line[7:intLen]
        elif (line.find('logdir') != -1):
            CON.logdir = line[7:intLen]  
        elif (line.find('modulesdir') != -1):
            CON.modulesdir = line[11:intLen]         
        elif (line.find('peaddin') != -1):
            CON.peaddins.append(line[8:intLen])
        elif (line.find('fileaddin') != -1):
            CON.fileaddins.append(line[10:intLen])
        elif (line.find('officeaddin') != -1):
            CON.msoaddins.append(line[12:intLen])
        elif (line.find('pdfaddin') != -1):
            CON.pdfaddins.append(line[9:intLen])
        elif (line.find('elfaddin') != -1):
            CON.elfaddins.append(line[9:intLen])
        else:
            if (CON.debug == True):
                print ''

    if (CON.debug == True):
        print 'Finished configuration.'
        print ''
            
    return 0

'''
Parse() - Parses program arguments
'''
def Parse(args):        
    option = ''
                    
    print '[*] Arguments: '
    for i in range(len(args)):
        if args[i].startswith('--'):
            option = args[i][2:]
                
            if option == 'help':
                return -1                                   

            if option == 'target':
                CON.target = args[i+1]
                print option + ': ' + CON.target

            if option == 'type':
                CON.type = args[i+1]
                print option + ': ' + CON.type            

            if option == 'modules':
                CON.modules = args[i+1]
                print option + ': ' + CON.modules

            if option == 'force':
                CON.force = True
                print option + ': ' + str(CON.force)

            if option == 'output':
                #This is an optional param and needs to be checked at read time
                CON.output = args[i+1]
                print option + ': ' + CON.output
                if len(CON.output) < 3:
                    print '[x] output must be a viable location'           
                    print ''
                    return -1
                
            if option == 'debug':
                CON.debug = True
                print option + ': ' + str(CON.debug)               

    #List modules will cause all other params to be ignored
    if option == 'listmodules':
        CON.listmodules = True
        print option + ': ' + str(CON.listmodules)
        print ''
    else:                                        
        #These are required params so length needs to be checked after all 
        #are read through     
        if len(CON.target) < 3:
            print 'target is a required argument'           
            print ''
            return -1         
    
        if len(CON.modules) < 3:
            print 'modules is a required argument'           
            print ''
            return -1

        if len(CON.type) < 2:
            print 'type is a required argument'           
            print ''
            return -1

        if ((CON.type.strip() != 'pe') and (CON.type != 'elf') and (CON.type != 'office') and (CON.type != 'pdf')):
            print '[x] Type ' + CON.type + ' is not supported\n'
            return -1   
                                   
    return 0

'''
ListModules()
Function: - List all available modules and their descriptions
'''
def ListModules():
    FConf = fileio()
    count = 0
    addins = ''

    for addins in CON.fileaddins:
        FConf.ReadFile(CON.modulesdir.strip() + addins.strip() + '.py')
        for line in FConf.fileobject:
            if (count == 1):
                print '[*] ' + addins + line
                count = 0
                break
            if (line.find('***BEGIN DESCRIPTION***') != -1):
                count = 1
             
    for addins in CON.peaddins:
        FConf.ReadFile(CON.modulesdir.strip() + addins.strip() + '.py')
        for line in FConf.fileobject:
            if (count == 1):
                print '[*] ' + addins + line
                count = 0
                break
            if (line.find('***BEGIN DESCRIPTION***') != -1):
                count = 1
    
    for addins in CON.msoaddins:
        FConf.ReadFile(CON.modulesdir.strip() + addins.strip() + '.py')
        for line in FConf.fileobject:
            if (count == 1):
                print '[*] ' + addins + line
                count = 0
                break
            if (line.find('***BEGIN DESCRIPTION***') != -1):
                count = 1   

    for addins in CON.pdfaddins:
        FConf.ReadFile(CON.modulesdir.strip() + addins.strip() + '.py')
        for line in FConf.fileobject:
            if (count == 1):
                print '[*] ' + addins + line
                count = 0
                break
            if (line.find('***BEGIN DESCRIPTION***') != -1):
                count = 1    

    for addins in CON.elfaddins:
        FConf.ReadFile(CON.modulesdir.strip() + addins.strip() + '.py')
        for line in FConf.fileobject:
            if (count == 1):
                print '[*] ' + addins + line
                count = 0
                break
            if (line.find('***BEGIN DESCRIPTION***') != -1):
                count = 1 

    return 0

'''
Terminate()
Function: - Attempts to exit the program cleanly when called  
'''     
def Terminate(exitcode):
    sys.exit(exitcode)

'''
main()
This is the mainline section of the program and makes calls to the 
various other sections of the code
'''    
if __name__ == '__main__':
    
        ret = 0

        CON = controller()
                   
        ret = Parse(sys.argv)

        if (ret == -1):
            Usage()
            Terminate(ret) 

        ret = ConfRead()        

        if (ret == -1):
            print 'Terminated reading the configuration file...'
            Terminate(ret)

        if (CON.listmodules == True):
            ListModules()
            Terminate(0)

        if len(CON.output) != 0:
            CON.logdir = CON.output.strip() + '/' + CON.target.strip() + '/'
        else:
            CON.logdir = CON.logdir.strip() + CON.target.strip() + '/'

        if (CON.logger.strip() == 'true'): 
            CON.logging = True
            print '[*] Logger is active'
            LOG = logger()
        else:
            print '[-] Logger not active'
                            

        if (CON.debug == True):
            print 'LOG variables:\n' 
            print 'logdir: ' + CON.logdir + '\n'
            print ''        

        if not os.path.exists(CON.logdir):
            os.makedirs(CON.logdir)
        else:
            print '[x] Sample: ' + CON.target + ' has previously been dealt with.  Terminating program.'
            Terminate(0)

        if (CON.logging == True):
            try:
                print '[*] Creating log file'
                LOG.LogCreate(CON.logdir, CON.target)                
            except Exception, e:
                print '[x] Unable to create LOG object: ', e
                Terminate(-1)
        
        if (CON.type == 'pe'):
            CON.peobject = peclass()
            CON.peobject.filename = CON.target
            PETRI = filetriage()
            CON.peobject = PETRI.Triage(CON.peobject, CON.logging, CON.logdir, CON.debug)

            if (CON.peobject.header.find('PE32') == -1):
                if (CON.force == True):   
                    print '[x] File type is not PE32 - analyzing anyway'
                else:                
                    print '[x] File type is not PE32 - Terminating'
                    Terminate (-1)
        elif (CON.type == 'office'):
            CON.msoobject = msoclass()
            CON.msoobject.filename = CON.target
            OFFTRI = filetriage()            
            CON.msoobject = OFFTRI.Triage(CON.msoobject, CON.logging, CON.logdir, CON.debug)

            if ((CON.msoobject.header.find('Microsoft Office') == -1) and (CON.msoobject.header.find('Microsoft Excel') == -1) and (CON.msoobject.header.find('Microsoft Word')==-1)):   
                if (CON.force == True):   
                    print '[x] File type is not MS Office - analyzing anyway'
                else:                
                    print '[x] File type is not MS Office - Terminating'
                    Terminate (-1)
        elif (CON.type == 'pdf'):
            CON.pdfobject = pdfclass()
            CON.pdfobject.filename = CON.target
            PDFTRI = filetriage()            
            CON.pdfobject = PDFTRI.Triage(CON.pdfobject, CON.logging, CON.logdir, CON.debug)

            if ((CON.pdfobject.header.find('PDF document') == -1)):   
                if (CON.force == True):   
                    print '[x] File type is not Portable Document Format (PDF) - analyzing anyway'
                else:                
                    print '[x] File type is not Portable Document Format (PDF) - Terminating'
                    Terminate (-1)
        elif (CON.type == 'elf'):
            CON.elfobject = elfclass()
            CON.elfobject.filename = CON.target
            ELFTRI = filetriage()            
            CON.elfobject = ELFTRI.Triage(CON.elfobject, CON.logging, CON.logdir, CON.debug)

            if (((CON.elfobject.header.find('ELF 32-bit LSB  executable')) == -1) and ((CON.elfobject.header.find('ELF 64-bit LSB  executable')) == -1)):   
                if (CON.force == True):   
                    print '[x] File type is not ELF - analyzing anyway'
                else:                
                    print '[x] File type is not ELF - Terminating'
                    Terminate (-1)

        CON.OrganizeModules()
    
        if (CON.debug==True):
	    print '[*] Program Complete'        
        if (CON.logging == True):
            newlogentry = 'Program Complete'
            LOG.WriteLog(CON.logdir, CON.target, newlogentry)
            newlogentry = ''
            LOG.LogFooter(CON.logdir, CON.target)
        Terminate(0)
'''
END OF LINE
'''
