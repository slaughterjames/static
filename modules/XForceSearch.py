#python imports
import sys
import os
import subprocess
import json
import requests
from requests.auth import HTTPBasicAuth
from termcolor import colored

#third-party imports
#No third-party imports

#programmer generated imports
from logger import logger
from fileio import fileio

'''
***BEGIN DESCRIPTION***
Type: Search - Description: Retrieves any available data for a target against the IBM XForce database.
***END DESCRIPTION***
'''
def POE(POE):
    
    APIKey = ''
    APIPassword = ''

    if (POE.logging == True): 
        LOG = logger() 
    newlogentry = ''
    xf_malflag = ''
    response_dump = ''
    xf = ''

    if (POE.logging == True):
        newlogentry = 'Module: XForceSearch'           
        LOG.WriteStrongLog(POE.logdir, POE.target, newlogentry)

    for apikeys in POE.apikeys: 
        for key, value in apikeys.items():
            if (POE.debug == True):
                print ('[DEBUG] API: ' + str(key) + ' | API Key: ' + str(value))
            if (key == 'xforceapi'):
                print ('\r\n[*] API key located!')
                APIKey = value
            if (key == 'xforcepassword'):
                print ('[*] API password located!')
                APIPassword = value

    if (APIKey == ''):
        print (colored('\r\n[x] An IBM X-Force Exchange API Key has not been input.  Create an account and generate an API Key and then apply to /opt/static/static.conf', 'red', attrs=['bold']))
        newlogentry = 'Unable to execute XForce reputation module - API Key/Password value not input.  Please add one to /opt/static/static.conf'
        LOG.WriteStrongSubLog(POE.logdir, POE.targetfilename, newlogentry)
        return -1

    if (APIPassword == ''):
        print (colored('\r\n[x] An IBM X-Force Exchange API Key Password has not been input.  Create an account and generate an API Key and then apply to /opt/static/static.conf', 'red', attrs=['bold']))
        newlogentry = 'Unable to execute XForce reputation module - API Key/Password value not input.  Please add one to /opt/static/static.conf'
        LOG.WriteStrongSubLog(POE.logdir, POE.targetfilename, newlogentry)
        return -1

    detectioncoverage = 0
    firstseen = ''
    lastseen = ''
    family = ''
    malwaretype = ''
    platform = ''
    subplatform = ''
    source = ''
    output = POE.logdir + 'XForceReport.json'

    FI = fileio()

    print (colored('[*] Running X-Force Search against: ' + POE.target, 'white', attrs=['bold']))

    if (POE.SHA256):
        xf = 'https://api.xforce.ibmcloud.com/malware/' + POE.SHA256
        print ('[*] SHA256 hash detected...')
    elif (POE.MD5):
        xf = 'https://api.xforce.ibmcloud.com/malware/' + POE.MD5
        print ('[*] MD5 hash detected...')
    elif (POE.SHA1):
        xf = 'https://api.xforce.ibmcloud.com/malware/' + POE.SHA1
        print ('[*] SHA1 hash detected...')
    else:
        print (colored('[x] A valid search hash is not present.  Terminating...', 'red', attrs=['bold']))
        return -1
  

    try:
        req = requests.get(xf, auth=HTTPBasicAuth(APIKey, APIPassword))      
        response_dump = json.loads(req.content.decode("UTF-8"))
    except requests.ConnectionError:
        print (colored('[x] Unable to connect to IBM X-Force\'s reputation site', 'red', attrs=['bold']))
        return -1

    if (req.status_code != 200):
        print (colored("[-] HTTP {} returned".format(req.status_code), 'yellow', attrs=['bold']))
        if (req.status_code == 404):
            print (colored('[-] Target not found in dataset...', 'yellow', attrs=['bold']))
        elif (req.status_code == 403):
            print (colored('[x] 403 Forbidden - something is wrong with the connection or credentials...', 'red', attrs=['bold']))       
        return -1                        
   
    try:        
        FI.WriteLogFile(output, json.dumps(response_dump, indent=4, sort_keys=True))
        print (colored('[*] X-Force search report data had been written to file here: ', 'green') + colored(output, 'blue', attrs=['bold']))
        if ((POE.logging == True) and (POE.nolinksummary == False)):
            newlogentry = 'X-Force search report data has been generated to file here: <a href=\"' + output + '\"> XForce Search Output </a>'
            LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)            
    except:
        print (colored('[x] Unable to write X-Force search data to file', 'red', attrs=['bold']))
        if (POE.logging == True):
            newlogentry = 'Unable to write X-Force search data to file'
            LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
        return -1

    try:
        detectioncoverage = response_dump['malware']['origins']['external']['detectionCoverage']
        firstseen = response_dump['malware']['origins']['external']['firstSeen']
        lastseen = response_dump['malware']['origins']['external']['lastSeen']
        family = response_dump['malware']['origins']['external']['family'][0]
        malwaretype = response_dump['malware']['origins']['external']['malwareType']
        source = response_dump['malware']['origins']['external']['source']
        platform = response_dump['malware']['origins']['external']['platform']
        print ('[*] Sample detection coverage: ' + str(detectioncoverage) + ' A/V vendors.')
        newlogentry = 'Sample detection coverage: ' + str(detectioncoverage) + ' A/V vendors.'
        LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
        print ('[*] Sample first seen: ' + firstseen)
        newlogentry = 'Sample first seen: ' + firstseen
        LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
        print ('[*] Sample last seen: ' + lastseen)
        newlogentry = 'Sample last seen: ' + lastseen
        LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
        print ('[*] Malware family: ' + family)
        newlogentry = 'Malware family: ' + family
        LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
        print ('[*] Malware type: ' + malwaretype)
        newlogentry = 'Malware type: ' + malwaretype
        LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
        print ('[*] Malware platform: ' + platform)
        newlogentry = 'Malware platform: ' + platform
        LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
        print ('[*] Malware source: ' + source)
        newlogentry = 'Sample source: ' + source
        LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
    except:
        print (colored('[-] JSON heading mismatch...', 'yellow', attrs=['bold']))

    return 0
