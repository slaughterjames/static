#! /usr/bin/env python3
'''
Static v0.3 - Copyright 2022 James Slaughter,
This file is part of Static v0.3.

Static v0.3 is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Static v0.3 is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Static v0.3.  If not, see <http://www.gnu.org/licenses/>.
'''

#python import
import sys
import os
import subprocess
import re
import json
import time
import datetime
import csv
from collections import defaultdict
from datetime import date
from array import *
from termcolor import colored

#programmer generated imports
from targetclass import targetclass
from filetriage import filetriage
#from portmap import portmap
from controller import controller
from logger import logger 
from fileio import fileio
from mms import mms

'''
Usage()
Function: Display the usage parameters when called
'''
def Usage():
    print ('Usage: [required] [--target|--targetfolder] --type --modules [all|specific] [optional] --sleeptime --output --nolinksummary --listmodules --listaddintypes --listapikeys --debug --help')
    print ('Example: /opt/static/static.py --target 123.exe --type \"triage pe\" --modules all --output /your/directory --debug')
    print ('Required Arguments:')
    print ('--target - Single file that will be analyzed')
    print ('OR')
    print ('--targetfolder - Folder containing multiple files to examine in one session')
    print ('--type - triage, search, fetch, pe, elf, office, lnk.  --triage can be used with every type except search and fetch by enclosing the statement in quotes \"\"')
    print ('--modules - all or specific')
    print ('Optional Arguments:')
    print ('--hash - MD5, SHA1 or SHA256 hash to use with --type search and --type fetch functions')
    print ('--force - Force analysis type even if the header details don\'t match')
    print ('--sleeptime - Choose the sleep period between targets when --targetfolder is used.  Default is 15 seconds.  Value must be between 0 and 120.')
    print ('--output - Choose where you wish the output to be directed')
    print ('--nolinksummary - Leave out links in the summary file to keep it clean and simple.')
    print ('--listmodules - Prints a list of available modules and their descriptions.')
    print ('--listaddintypes - Prints a list of available addin types as defined in the mirage.conf file.  Defines a group of modules to run.')
    print ('--listapikeys - Prints a list of available API Keys.')
    print ('--debug - Prints verbose logging to the screen to troubleshoot issues with a recon installation.')
    print ('--help - You\'re looking at it!')
    sys.exit(-1)

'''
ConfRead()
Function: - Reads in the intelscraper.conf config file and assigns some of the important
            variables
'''
def ConfRead():
        
    ret = 0
    intLen = 0
    FConf = fileio()
    data = ''

    try:
        #Conf file hardcoded here
        with open('/opt/static/static.conf', 'r') as read_file:
            data = json.load(read_file)
    except:
        print (colored('[x] Unable to read configuration file.', 'red', attrs=['bold']))
        return -1

    
    CON.logger = data['logger']
    CON.logroot = data['logroot']
    CON.useragent = data['useragent']
    CON.useragent = CON.useragent.strip()
    CON.yararulesdirectory = data['yararulesdirectory']
    CON.yararulesdirectory = CON.yararulesdirectory.strip()
    CON.sleeptime = data['sleeptime']
    if ((int(CON.sleeptime.strip()) < 0) or (int(CON.sleeptime.strip()) > 120)):
        CON.sleeptime = '7'
        print (colored('[x] sleeptime value out of range.  sleeptime must be between 0 and 120 seconds.', 'red', attrs=['bold']))
        print (colored('[-] sleeptime defaulting to 7 seconds.', 'yellow', attrs=['bold']))
    CON.modulesdir = data['modulesdir']
    CON.apikeys = data['apikeys']
    CON.types = data['addintypes']
    CON.addins = data['addins']
  
    if (CON.debug == True):
        print ('[DEBUG] data: ', data)
        print ('[DEBUG] CON.logger: ' + str(CON.logger))
        print ('[DEBUG] CON.logroot: ' + str(CON.logroot))
        print ('[DEBUG] CON.useragent: ' + str(CON.useragent))
        print ('[DEBUG] CON.sleeptime: ' + str(CON.sleeptime))
        print ('[DEBUG] CON.modulesdir: ' + str(CON.modulesdir))
        print ('[DEBUG] CON.types: ' + str(CON.types))
 
        for a_addins in CON.addins: 
            #for key, value in a_addins.iteritems():
            for key, value in a_addins.items():
                print ('[DEBUG] CON.addins key: ' + key + ' value: ' + value)

        for a_apikeys in CON.apikeys: 
            #for key, value in a_addins.iteritems():
            for key, value in a_apikeys.items():
                print ('[DEBUG] CON.apikeys key: ' + key + ' value: ' + value)
            
    if (CON.debug == True):
       print ('[*] Finished configuration.')
       print ('')

    return 0
            
'''
Parse() - Parses program arguments
'''
def Parse(args):        
    option = ''

    print ('[*] Length Arguments: ' + str(len(args)))

    if (len(args) == 1):
        return -1

    print ('[*] Arguments: ')
    for i in range(len(args)):
        if args[i].startswith('--'):
            option = args[i][2:]
                
            if option == 'help':
                return -1                                   

            if option == 'target':
                CON.target = args[i+1]
                CON.singletarget = True
                print (option + ': ' + CON.target)

            if option == 'targetfolder':
                CON.targetfolder = args[i+1]
                CON.singletarget = False
                print (option + ': ' + CON.targetfolder) 

            if option == 'type':
                CON.type = args[i+1].split()
                for type_out in CON.type:
                    print (option + ': ' + type_out)
                    if (type_out == 'search'):
                        CON.search = True
                    if (type_out == 'fetch'):
                        CON.fetch = True  

            if option == 'modules':
                CON.modules = args[i+1]
                print (option + ': ' + CON.modules)

            if option == 'hash':
                CON.hash = args[i+1]
                print (option + ': ' + str(CON.hash))

            if option == 'sleeptime':
                CON.sleeptime = args[i+1]
                print (option + ': ' + str(CON.sleeptime))

            if option == 'force':
                CON.force = True
                print (option + ': ' + str(CON.force))
            
            if option == 'output':
                #This is an optional param and needs to be checked at read time
                CON.output = args[i+1]
                print (option + ': ' + CON.output)
                if len(CON.output) < 3:
                    print (colored('[x] output must be a viable location.', 'red', attrs=['bold']))
                    print ('')
                    return -1

            if option == 'nolinksummary':
                CON.nolinksummary = True
                print (option + ': ' + str(CON.nolinksummary))
                
            if option == 'debug':
                CON.debug = True
                print (option + ': ' + str(CON.debug))               

    #listmodules, listaddintypes and listapikeys will cause all other params to be ignored
    if option == 'listmodules':
        CON.listmodules = True
        print (option + ': ' + str(CON.listmodules))
        print ('')

    elif option == 'listaddintypes':
        CON.listaddintypes = True
        print (option + ': ' + str(CON.listaddintypes))
        print ('')

    elif option == 'listapikeys':
        CON.listapikeys = True
        print (option + ': ' + str(CON.listapikeys))
        print ('')

    else:
        #These params cannot be used concurrently
        if ((CON.search == True) and (CON.fetch == True)):
            print (colored('[x] search and fetch cannot be used simultaneously.', 'red', attrs=['bold']))
            print ('')
            return -1 
            
        #These params will only be checked if we're not searching or fetching...
        if ((CON.search == False) and (CON.fetch == False)):
            if ((len(CON.target) < 3) and (len(CON.targetfolder) < 3) and (len(CON.hash) < 3)):
                print (colored('[x] target, targetfolder or hash are required arguments.', 'red', attrs=['bold']))
                print ('')
                return -1         

            if ((len(CON.target) > 0) and (len(CON.targetfolder) > 0)):
                print (colored('[x] target argument cannot be used with targetfolder.', 'red', attrs=['bold']))
                print ('')
                return -1

            if ((len(CON.target) > 0) and (len(CON.hash) > 0)):
                print (colored('[x] target argument cannot be used with hash.', 'red', attrs=['bold']))
                print ('')
                return -1

            if ((len(CON.targetfolder) > 0) and (len(CON.hash) > 0)):
                print (colored('[x] targetfolder argument cannot be used with hash.', 'red', attrs=['bold']))
                print ('')
                return -1

        #These are required params so length needs to be checked after all 
        #are read through 

        if len(CON.modules) < 3:
            print (colored('[x] modules is a required argument.', 'red', attrs=['bold']))
            print ('')
            return -1

        if len(CON.type) < 1:
            print (colored('[x] type is a required argument.', 'red', attrs=['bold']))
            print ('')
            return -1 

        if ((CON.search == True) and (len(CON.hash) < 3)):
            print (colored('[x] hash must be used with type search.', 'red', attrs=['bold']))
            print ('')
            return -1

        if ((CON.fetch == True) and (len(CON.hash) < 3)):
            print (colored('[x] hash must be used with type fetch.', 'red', attrs=['bold']))
            print ('')
            return -1 

        if (CON.sleeptime != ''):
            if ((int(CON.sleeptime.strip()) < 0) or (int(CON.sleeptime.strip()) > 120)):
                print (colored('[x] sleeptime value out of range.  sleeptime must be between 0 and 120 seconds.', 'red', attrs=['bold']))
                print ('')
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

    for addins in CON.addins: 
        #for key, value in addins.iteritems():
        for key, value in addins.items():
            FConf.ReadFile(CON.modulesdir.strip() + value.strip() + '.py')
            for line in FConf.fileobject:
                if (count == 1):
                    print ('[*] ' + value + ': ' + line)
                    count = 0
                    break
                if (line.find('***BEGIN DESCRIPTION***') != -1):
                    count = 1              

    return 0

'''
ListAddinTypes()
Function: - List all available addin types
'''
def ListAddinTypes():
    FConf = fileio()
    count = 0
    addins = ''

    print ('[*] Addin types available are:\n')
    for type_out in CON.types:
        print ('[*] Type: ' + type_out)

    return 0

'''
ListAPIKeys()
Function: - List all available API Keys
'''
def ListAPIKeys():
    FConf = fileio()
    count = 0
    addins = ''

    for apikeys in CON.apikeys: 
        #for key, value in addins.iteritems():
        for key, value in apikeys.items():
            print ('API: ' + str(key) + ' | API Key: ' + str(value))
            
    return 0

'''
TargetRead()
Function: - Reads in a list of targets from a folder
'''
def TargetRead():

    #FConf = fileio()
    try:
        #Conf file hardcoded here
    	paths = [os.path.join(CON.targetfolder, fn) for fn in next(os.walk(CON.targetfolder))[2]]
    except:
        print ('[x] Unable to read target folder: ' + CON.targetlist)
        print (colored('[x] Unable to read target folder: ' + CON.targetlist, 'red', attrs=['bold']))
        return -1
    
    for line in paths:
        CON.listoftargets.append(line)
        if (CON.debug == True):
            print ('[DEBUG]: ' + line)

    CON.targetlistsize = len(CON.listoftargets)
        
    print ('[*] Finished walking target folder.')
    print ('[*] Target list size: ' + str(CON.targetlistsize) + ' entries.')
    print ('')
            
    return 0

'''
Execute()
Function: - Does the doing against a target
'''
def Execute():

    if ((CON.search == True) or (CON.fetch == True)):
        if (len(CON.output) != 0):
            CON.logdir = CON.output.strip() + '/' + CON.hash.strip() + '/'
            CON.targetobject.logdir = CON.output.strip() + '/' + CON.hash.strip() + '/'
        else:
            CON.logdir = CON.logroot.strip() + '/' + CON.hash.strip() + '/'
            CON.targetobject.logdir = CON.logroot.strip() + '/' + CON.hash.strip() + '/'
        if (len(CON.target) < 40):
            CON.targetobject.MD5 = CON.target
        elif ((len(CON.target) > 39) and (len(CON.target) < 50)):
            CON.targetobject.SHA1 = CON.target
        elif (len(CON.target) > 50):
            CON.targetobject.SHA256 = CON.target
        else:
            print (colored('[x] The hash structure is not correct.  Terminating...', 'red', attrs=['bold']))
            return -1
    elif (len(CON.output) != 0):
        if ((CON.fetch == False) and (CON.search == False)):
            CON.logdir = CON.output.strip() + '/' + os.path.basename(CON.targetobject.target.strip()) + '/'
            CON.targetobject.logdir = CON.output.strip() + '/' + os.path.basename(CON.targetobject.target.strip()) + '/'
    else:
        CON.logdir = CON.logroot.strip() + os.path.basename(CON.targetobject.target.strip()) + '/'
        CON.targetobject.logdir = CON.logroot.strip() + os.path.basename(CON.targetobject.target.strip()) + '/'

    if (CON.logging == True):
        LOG = logger()                           

    if (CON.debug == True):
        print ('LOG variables:\n')
        print ('logdir: ' + CON.logdir + '\n')
        print ('')

    if not os.path.exists(CON.logdir):
        os.makedirs(CON.logdir)
    else:
        CON.targetdealtwith = True
        print (colored('[-] Target: ' + CON.targetobject.target + ' has previously been dealt with...Skipping.', 'yellow', attrs=['bold']))
        return -1

    if (CON.logging == True):
        try:
            print ('[*] Creating log file')
            LOG.SummaryCreate(CON.logdir, CON.targetobject.targetfilename)                
        except:
            print ('[x] Unable to create LOG object for summary file!')
            print (colored('[x] Unable to create LOG object for summary file!', 'red', attrs=['bold']))

    if (CON.search == True):
        print ('[-] Search active...skipping triage')
    elif (CON.fetch == True):
        print ('[-] Fetch active...skipping triage')
    elif (('triage' in CON.type) and (CON.search == False)):
        TRI = filetriage()
        CON.targetobject = TRI.triage(CON.targetobject, CON.logging, CON.logdir, CON.nolinksummary, CON.debug)
    else:
        TRI = filetriage()
        CON.targetobject = TRI.triage(CON.targetobject, CON.logging, CON.logdir, CON.nolinksummary, CON.debug)

        if ('pe' in CON.type):
            if (CON.debug == True):
                print ('[DEBUG] CON.targetobject.header: ' + CON.targetobject.header)
            if (CON.targetobject.header.find('PE32') == -1):
                if (CON.force == True):   
                    print ('[x] File type is not PE32 - analyzing anyway...')
                else:
                    print ('[x] File type is not PE32 - Terminating. Use --force to continue analysis...')
                    Terminate (-1)
        elif ('office' in CON.type ):
            if (CON.debug == True):
                print ('[DEBUG] CON.targetobject.header: ' + CON.targetobject.header)
            if ((CON.targetobject.header.find('Microsoft Office') == -1) and (CON.targetobject.header.find('Microsoft Excel') == -1) and (CON.targetobject.header.find('Microsoft Word')==-1)):   
                if (CON.force == True):   
                    print ('[x] File type is not MS Office - analyzing anyway...')
                else:                
                    print ('[x] File type is not MS Office - Terminating. Use --force to continue analysis...')
                    Terminate (-1)        
        elif ('pdf' in CON.type):
            if (CON.debug == True):
                print ('[DEBUG] CON.targetobject.header: ' + CON.targetobject.header)
            if ((CON.targetobject.header.find('PDF document') == -1)):
                if (CON.force == True):   
                    print ('[x] File type is not Portable Document Format (PDF) - analyzing anyway...')
                else:                
                    print ('[x] File type is not Portable Document Format (PDF) - Terminating. Use --force to continue analysis...')
                    Terminate (-1)
        elif ('elf' in CON.type):
            if (CON.debug == True):
                print ('[DEBUG] CON.targetobject.header: ' + CON.targetobject.header)
            if (((CON.targetobject.header.find('ELF 32-bit LSB  executable')) == -1) and ((CON.targetobject.header.find('ELF 64-bit LSB  executable')) == -1)):   
                if (CON.force == True):   
                    print ('[x] File type is not ELF - analyzing anyway...')
                else:                
                    print ('[x] File type is not ELF - Terminating. Use --force to continue analysis...')
                    Terminate (-1)
        elif ('lnk' in CON.type):
            if (CON.debug == True):
                print ('[DEBUG] CON.targetobject.header: ' + CON.targetobject.header)
            if (CON.targetobject.header.find('MS Windows shortcut') == -1):   
                if (CON.force == True):   
                    print ('[x] File type is not LNK - analyzing anyway...')
                else:                
                    print ('[x] File type is not LNK - Terminating. Use --force to continue analysis...')
                    Terminate (-1)       

    ret = MMS.OrganizeModules(CON.targetobject)
    if (ret !=0 ):
        print ('[x] Unable to continue module execution.  Terminating...')
        print (colored('[x] Unable to continue module execution.  Terminating...', 'red', attrs=['bold']))
        Terminate(ret) 

    if (CON.logging == True):
        newlogentry = ''
        LOG.WriteSummary(CON.logdir, CON.targetobject.targetfilename, newlogentry)
        newlogentry = 'Program Complete'
        LOG.WriteSummary(CON.logdir, CON.targetobject.targetfilename, newlogentry)
        newlogentry == ''
        LOG.SummaryFooter(CON.logdir, CON.targetobject.targetfilename)

    CON.logdir = ''

'''
Terminate()
Function: - Attempts to exit the program cleanly when called  
'''
     
def Terminate(exitcode):
    sys.exit(exitcode)

'''
This is the mainline section of the program and makes calls to the 
various other sections of the code
'''

if __name__ == '__main__':
    
    ret = 0

    Table_Data = ()

    CON = controller()
                   
    ret = Parse(sys.argv)

    if (ret == -1):
        Usage()
        Terminate(ret) 

    ret = ConfRead()        

    if (ret == -1):
        print ('[x] Terminated reading the configuration file...')
        Terminate(ret)

    if (CON.listmodules == True):
        ListModules()
        Terminate(0)

    if (CON.listaddintypes == True):
        ListAddinTypes()
        Terminate(0)

    if (CON.listapikeys == True):
        print ('apikeys') 
        ListAPIKeys()
        Terminate(0)

    for type in CON.type:
        if (CON.debug == True):
            print ('[DEBUG] Type: ' + type)
        if (type in CON.types):
            print ('[*] Type is ' + type)
            for addins in CON.addins: 
                for key, value in addins.items():
                    if (key == type):
                        CON.module_manifest.append(value)
            MMS = mms(CON.module_manifest, CON.modulesdir, CON.modules, CON.debug) 
        else:
            print (colored('[x] Type ' + type + ' is not recognized...\n', 'red', attrs=['bold']))
            print ('Type must be one of the following:')
            for types in CON.types:
                print (types)
            print ('[x] Terminating...')
            Terminate(-1)

    if (CON.debug == True):
        print ('[DEBUG]: ', CON.module_manifest)

    if (CON.logger.strip() == 'true'): 
        CON.logging = True
        print ('[*] Logger is active')
    else:
        print ('[-] Logger not active')

    if ((CON.search == True) or (CON.fetch == True)):
        CON.target = CON.hash 
        CON.targetfilename = CON.hash
        CON.targetobject = targetclass(CON.logging, CON.debug, CON.nolinksummary, CON.target, CON.targetfilename, CON.useragent, CON.yararulesdirectory, CON.force, CON.apikeys)
        Execute()
        del CON.targetobject
    elif ((CON.singletarget == True) and (CON.search == False) and (CON.fetch == False)):
        CON.targetfilename = os.path.basename(CON.target.strip())
        CON.targetobject = targetclass(CON.logging, CON.debug, CON.nolinksummary, CON.target, CON.targetfilename, CON.useragent, CON.yararulesdirectory, CON.force, CON.apikeys)
        Execute()
        del CON.targetobject
    else:
        TargetRead()
        Count = 0
                       
        if (CON.logging == True):
            if len(CON.output) != 0:
                CON.reportdir = CON.output.strip() + '/'
            else:
                CON.reportdir = CON.logroot.strip() + '/'  

            if not os.path.exists(CON.reportdir):
                os.makedirs(CON.reportdir)    
         
            try: 
                if (CON.csv == True):
                    CON.csv_filename = CON.reportdir + 'logroot.csv'
 
                    if (CON.debug == True):
                        print ('[DEBUG]: CSV Field Names: ', CON.module_manifest)

                    with open(CON.csv_filename, mode='wb') as logroot_file:
                        logroot_writer = csv.DictWriter(logroot_file, fieldnames=["Target"] + CON.module_manifest)
                        logroot_writer.writeheader()                                               
            except:
                print ('[x] Unable to create CSV File!')
                Terminate(-1)  
              
        for target in CON.listoftargets:
            Count += 1

            CON.targetobject = targetclass(CON.logging, CON.debug, CON.nolinksummary, CON.target, CON.targetfilename, CON.useragent, CON.yararulesdirectory, CON.force, CON.apikeys)
            CON.targetobject.target = target.strip()
            CON.targetfilename = os.path.basename(CON.targetobject.target.strip())
            CON.targetobject.targetfilename = CON.targetfilename

            print ('[*] Executing against target ' + str(Count) + ' of ' + str(CON.targetlistsize) + ' - ' + CON.targetobject.target + '\r')

            if (CON.csv == True):
                CON.targetobject.csv_line += CON.targetobject.target + ','
 
            Execute()                

            if (CON.debug==True):
                print ('[DEBUG]: ' + target)

            if (CON.logging == True):
                target_link = '<a href=\"' + CON.logdir + CON.targetobject.targetfilename + '/' + CON.targetobject.targetfilename + '.html' + '\">' + CON.targetobject.targetfilename + '</a>'
                if (CON.csv == True):
                    f = open(CON.csv_filename,'a')
                    f.write(CON.targetobject.csv_line + '\n')
                    f.close()                

            del CON.targetobject
            if (CON.targetdealtwith == False):
                if (Count != CON.targetlistsize):
                    print ('[*] Sleeping ' + CON.sleeptime.strip() + ' seconds before next request...')
                    print ('*' * 100)
                    time.sleep(int(CON.sleeptime.strip()))
            else:
                CON.targetdealtwith = False


    print ('')
    print (colored('[*] Program Complete', 'green', attrs=['bold']))

    Terminate(0)
'''
END OF LINE
'''
