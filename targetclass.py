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
targetclass.py - This file is responsible for the creation of the targetclass
'''

#python imports
from array import *

#programmer generated imports


'''
targetclass
Class: This class is responsible for holding the data for a given target under
       investigation and then populating the appropriate values for use elsewhere 
       in the code
'''
class targetclass:
    '''
    Constructor
    '''
    def __init__(self, logging, debug, nolinksummary, target, targetfilename, useragent, yararulesdirectory, force, apikeys):

        self.target = ''
        self.targetfilename = ''
        self.useragent = useragent
        self.yararulesdirectory = yararulesdirectory
        self.logdir = ''
        self.logging = False
        self.debug = False
        self.nolinksummary = False
        self.MD5 = ''
        self.SHA1 = ''
        self.SHA256 = ''
        self.filename = ''
        self.filesize = ''
        self.header = ''
        self.extension = ''
        self.macros = []
        self.force = False
        self.apikeys = []

        self.logging = logging
        self.debug = debug
        self.nolinksummary = nolinksummary
        self.target = target
        self.targetfilename = targetfilename
        self.useragent = useragent
        self.force = force 
        self.apikeys = apikeys                     
