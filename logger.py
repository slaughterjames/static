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
logger.py - This file is responsible for providing a mechanism to write 
log files to the hard drive and read in the static.conf file


logger
Class: This class is responsible for providing a mechanism to write
       log files to the hard drive and read in the static.conf file
       - Uncomment commented lines in the event troubleshooting is required
        
'''

#python imports
import sys
import os
import datetime

#programmer generated imports
from fileio import fileio

class logger:
    
    '''
    Constructor
    '''
    def __init__(self):
        
        self.startdatetime = ''  

    '''
    LogCreate()
    Function: - Creates a new log based on the FuzzID
              - Adds a header to the log 
              -  
    '''     
    def LogCreate(self, logdir, target):  
        logroot = logdir + 'logroot.html'
        FLog = fileio()
        
        self.startdatetime = datetime.datetime.now().strftime("%I:%M%p on %B %d, %Y")
        filename = logdir + target + '.html'
        data = '<html>\n'
        data += '\n--------------------------------------------------------------------------------'
        data += '---------------------------------------<br/>'
        data += '<head>\n<title>' + filename + '</title>\n'
        data += '\n<strong>Starting Analysis On: </strong><br/>\n' + '\n' + '<strong>Sample: </strong>' + target
        data += ' <strong>Date/Time: </strong>' + self.startdatetime + '<br/>\n'
        data += '--------------------------------------------------------------------------------'
        data += '---------------------------------------<br/>\n</head>\n<body>\n'
        FLog.WriteNewLogFile(filename, data)
           
        return 0   
    
    '''
    LogFooter()
    Function: - Adds a footer to close out the log file created in the function above
              - 
              -  
    '''     
    def LogFooter(self, logdir, target):  
        FLog = fileio()
        self.startdatetime = datetime.datetime.now().strftime("%I:%M%p on %B %d, %Y")
        filename = logdir + target + '.html'        
        data = '<strong>END OF FILE</strong><br/>'
        data += '--------------------------------------------------------------------------------'
        data += '---------------------------------------\n<br/>'
        data += 'Processed by Static v0.1\n<br/>'
        data += '--------------------------------------------------------------------------------'
        data += '---------------------------------------\n<br/>'
        data += '\n</body>\n</html>\n'
        FLog.WriteLogFile(filename, data)
        print '[*] Log file written to: ' + filename
           
        return 0       
        
    '''    
    WriteLog()
    Function: - Writes to the current log file            
              - Returns to the caller
    '''    
    def WriteLog(self, logdir, target, newlogline):  
        FLog = fileio()
        nowdatetime = datetime.datetime.now().strftime("%I:%M%p on %B %d, %Y")
        filename = logdir + target + '.html'
        data = nowdatetime + ' ' + newlogline + '\n<br/>'
        FLog.WriteLogFile(filename, data)
           
        return 0 
    

        
