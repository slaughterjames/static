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
controller.py - This file is responsible for the dynamic loading of static's modules
'''

#python imports
import imp
import sys
from array import *

#programmer generated imports
from logger import logger

'''
controller
Class: This class is responsible for the dynamic loading of static's modules
'''
class controller:
    '''
    Constructor
    '''
    def __init__(self):

        self.target = ''
        self.debug = False
        self.force = False
        self.peobject = ''
        self.emlobject = ''
        self.msoobject = ''
        self.pdfobject = ''
        self.elfobject = ''
        self.pythonbase = ''
        self.fileaddins = []
        self.peaddins = []
        self.emailaddins = []
        self.msoaddins = []
        self.pdfaddins = []
        self.elfaddins = []
        self.type = ''
        self.modules = ''
        self.modulesdir = ''
        self.output = ''
        self.logdir = ''
        self.logger = ''
        self.logging = False
        self.listmodules = False
        
    '''       
    ExecuteModules()
    Function: - Determines if all required arguments are present
              - Populates the required variables and determines the protocol if not specified
              - returns to calling fuzzer 
              - Uncomment print items to aid in troubleshooting
    '''    
    def ExecuteModules(self, modules):        
        option = ''
        mymod = ''
      
        #Locate the dynamic module, create a file object for it
        try:
            fp, pathname, description = imp.find_module(modules, [self.modulesdir.strip()])
            print '\n[*] Module ' + modules + ' located'
            if (self.debug == True):
                print '\n[DEBUG] fp: ' + str(fp) + ' pathname: ' + str(pathname) + ' description: ' + str(description) + '\n'   
        except ImportError:
            print '[x] Unable to locate module: ' + modules

        #Load the module into memory
    	try:
            mymod = imp.load_module(modules, fp, pathname, description)
            print '[*] Module ' + modules + ' loaded successfully'
        except Exception, e:
            print '[x] Unable to load module: ', e      
        finally:
            fp.close()  

        #Execute the module
        try:
            print '[*] Executing module'
            if (self.type == 'pe'):
                mymod.POE(self.logdir, self.peobject, self.logging, self.debug)
            elif (self.type == 'pdf'):
                mymod.POE(self.logdir, self.pdfobject, self.logging, self.debug)
            elif (self.type == 'elf'):
                mymod.POE(self.logdir, self.elfobject, self.logging, self.debug)
            elif (self.type == 'office'):
                mymod.POE(self.logdir, self.msoobject, self.logging, self.debug)
        except Exception, e:
            print '[x] Unable to load module: ', e  
            return -1
                                         
        return 0


    '''       
    OrganizeModules()
    Function: - Cycles through the arrays of available modules
              - Sends the chosen one on to execution
    ''' 
    def OrganizeModules(self):
        print '[*] Organize Modules'

        #Make sure when the 'all' modifier is selected, the fileaddins are run along with the ones from each file type
        if (((self.type == 'pe') or (self.type == 'office') or (self.type == 'pdf') or (self.type == 'elf')) and (self.modules == 'all')):
            for fileaddins_data in self.fileaddins:                
                if (self.debug == True):
                    print '[DEBUG] File Module: ' + fileaddins_data    
                self.ExecuteModules(fileaddins_data.strip())

        if ((self.type == 'pe') and (self.modules == 'all')):
            for peaddins_data in self.peaddins:                
                if (self.debug == True):
                    print '[DEBUG] PE Module: ' + peaddins_data    
                self.ExecuteModules(peaddins_data.strip())

        if ((self.type == 'office') and (self.modules == 'all')):
            for msoaddins_data in self.msoaddins:                
                if (self.debug == True):
                    print '[DEBUG] MS Office Module: ' + msoaddins_data    
                self.ExecuteModules(msoaddins_data.strip())

        if ((self.type == 'pdf') and (self.modules == 'all')):
            for pdfaddins_data in self.pdfaddins:
                if  (self.debug == True):
                    print '[DEBUG] PDF Module: ' + pdfaddins_data    
                self.ExecuteModules(pdfaddins_data.strip())

        if ((self.type == 'elf') and (self.modules == 'all')):
            for elfaddins_data in self.elfaddins:
                if  (self.debug == True):
                    print '[DEBUG] ELF Module: ' + elfaddins_data    
                self.ExecuteModules(elfaddins_data.strip())

        if (((self.type == 'pe') or (self.type == 'office') or (self.type == 'pdf') or (self.type == 'elf')) and (self.modules != 'all')):
            print '[*] Module ' + self.modules
            self.ExecuteModules(self.modules)     

        return 0
        


         

