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
msoclass
Class: This class is responsible for providing an object to hold details of a target
Microsoft Office file
'''
class msoclass:
    '''
    Constructor
    '''
    def __init__(self):

        self.MD5 = ''
        self.SHA256 = ''
        self.filename = ''
        self.header = ''
        self.macros = [] 

'''
pdfclass
Class: This class is responsible for providing an object to hold details of a target
PDF file
'''
class pdfclass:
    '''
    Constructor
    '''
    def __init__(self):

        self.MD5 = ''
        self.SHA256 = ''
        self.filename = ''
        self.header = ''

'''
peclass
Class: This class is responsible for providing an object to hold details of a target
PE file
'''
class peclass:
    '''
    Constructor
    '''
    def __init__(self):

        self.MD5 = ''
        self.SHA256 = ''
        self.filename = ''
        self.header = '' 

'''
elfclass
Class: This class is responsible for providing an object to hold details of a target
ELF file
'''
class elfclass:
    '''
    Constructor
    '''
    def __init__(self):

        self.MD5 = ''
        self.SHA256 = ''
        self.filename = ''
        self.header = '' 
