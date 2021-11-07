#python imports
#standard widely used classes, add  or remove as needed
import sys
import os
import subprocess
import jsons

#third-party imports

#programmer generated imports
#This is my log generator, you could easily replace with your own
from logger import logger
#This is the static file read and log write class - again, you could use the Python 
#standard or implement your own
from fileio import fileio

'''
***BEGIN DESCRIPTION***
Type: Triage|Search|Office|PE|ELF - Description: Add a description of what your addin module does
***END DESCRIPTION***
'''
def POE(POE):
#POE = Point Of Entry - where the main static code interfaces with this module
#This is an object being fed from the targetclass object.
#See targetclass.py for a list of object members.

    #Add your code here

    #This will instantiate the built-in logging mechanism.
    #if (POE.logging == True): 
    #    LOG = logger() 

    #By uncommenting this, you will create a entry in the main log summary HTML file
    #if (POE.logging == True):
    #    newlogentry = 'Module: Your Module'           
    #    LOG.WriteStrongLog(POE.logdir, POE.targetfilename, newlogentry)
    
    #You'll need to leave the return in to exit gracefully.  If you wanted to signal an issue, use return -1.
    return 0
