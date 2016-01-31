#python imports
#standard widely used classes, add  or remove as needed
import sys
import os
import subprocess

#third-party imports

#programmer generated imports
#This is my log generator, you could easily replace with your own
from logger import logger
#This is the static file read and log write class - again, you could use the Python 
#standard or implement your own
from fileio import fileio

'''
***BEGIN DESCRIPTION***
Add a description of what your addin module does
***END DESCRIPTION***
'''
def POE(logdir, target, logging, debug):
#POE = Point Of Entry - where the main static code interfaces with this module
#logdir - Any potential output will go here
#target - Target file to be analyzed.  Class attributes include MD5, SHA256, filename and header.  Example, "target.filename"
#logging - The logging flag,  it it has been turned on, logging can occur whether using the provided logger class or you use your own.
#debug - The debug flag, if turned on, debug logging can be added

    #Add your code here

    #Example Log Line
    #if (logging == True): 
    #    LOG = logger() 
    #newlogentry = ''
    #if (logging == True):
        #newlogentry = 'My log line'
        #LOG.WriteLog(logdir, target.filename, newlogentry)
    

    return 0
