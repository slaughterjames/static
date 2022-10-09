#python imports
import sys
import os
import time
import datetime
import subprocess
import json
import requests
from termcolor import colored

#third-party imports
#No third-party imports

#programmer generated imports
from logger import logger
from fileio import fileio

'''
***BEGIN DESCRIPTION***
Type: Triage - Description: Searches for any available data on a target against the CERT.PL malware database.
***END DESCRIPTION***
'''
def POE(POE):

    if (POE.logging == True): 
        LOG = logger() 
    newlogentry = ''
    reputation_dump = ''
    reputation_output_data = ''
    certpl = ''

    if (POE.logging == True):
        newlogentry = 'Module: CERTPL_search'           
        LOG.WriteStrongLog(POE.logdir, POE.targetfilename, newlogentry)

    for apikeys in POE.apikeys: 
        for key, value in apikeys.items():
            if (POE.debug == True):
                print ('[DEBUG] API: ' + str(key) + ' | API Key: ' + str(value))
            if (key == 'certpl'):
                print ('\r\n[*] API key located!')
                apikey = value

    if (apikey == ''):
        print (colored('\r\n[x] Unable to execute CERTPL_search - apikey value not input.  Please add one to /opt/static/static.conf', 'red', attrs=['bold']))
        if (logging == True):
            newlogentry = 'Unable to execute CERTPL_search - apikey value not input.  Please add one to /opt/static/static.conf'
            LOG.WriteStrongSubLog(POE.logdir, POE.targetfilename, newlogentry)
            POE.csv_line += 'N/A,'
        return -1

    global json
    message = ''
    upload_time = ''
    file_type = ''
    tag0 = ''
    tag1 = ''
    output = POE.logdir + 'CERTPL_search.json'

    FI = fileio()
    
    print (colored('\r\n[*] Running CERT.PL_search against: ' + POE.target, 'white', attrs=['bold']))

    certpl = "https://mwdb.cert.pl/api/file/" + POE.SHA256 #API URL
    headers = { #Our header params
      'accept': 'application/json',
      'Authorization': 'Bearer  %s' %apikey
    }

    response = requests.Session()
    response_dump = response.get(certpl, headers={'accept': 'application/json','Authorization': 'Bearer ' + apikey}) # Give us the results as JSON

    if (POE.debug == True):
        print ('[DEBUG] response_dump: ' + str(response_dump))

    if (POE.debug == True):
        print ('[DEBUG] response_dump.content: ' + str(response_dump.content))

    try:        
        FI.WriteLogFile(output, response_dump.content.decode("utf-8", "ignore"))
        print (colored('[*] CERTPL_search data had been written to file here: ', 'green') + colored(output, 'blue', attrs=['bold']))
        if ((POE.logging == True) and (POE.nolinksummary == False)):
            newlogentry = 'CERTPL_search data has been generated to file here: <a href=\"' + output + '\"> CERTPL_search Output </a>'           
            LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
    except:
        print (colored('[x] Unable to write CERTPL_search data to file', 'red', attrs=['bold']))
        if (POE.logging == True):
            newlogentry = 'Unable to write CERTPL_search data to file'
            LOG.WriteStrongSubLog(POE.logdir, POE.targetfilename, newlogentry)
        return -1

    try:
        #Open the file we just downloaded
        print ('[-] Reading CERTPL_search file: ' + output.strip())

        with open(output.strip(), 'rb') as read_file:
            data = json.load(read_file, cls=None)
        read_file.close()

        # Check what kind of results we have
        try:
            message = data["message"]      
            print ('[*] message: ' + message)
        except Exception as e:
            if (POE.debug == True):            
                print (colored('[DEBUG] Error: ' + str(e) + ' Continuing...', 'red', attrs=['bold']))

        if (message == 'Object not found'):
            print (colored('[-] No results available for host...', 'yellow', attrs=['bold']))
            if (POE.logging == True):
                newlogentry = 'No results available for host...'
                LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
        else:
            with open(output.strip(), 'r') as read_file:
                for string in read_file:
                    if (POE.debug == True):
                        print ('[DEBUG] string: ' + string.strip())
            upload_time = data["upload_time"]
            file_type = data["file_type"]
            tag0 = data["tags"][0]
            tag0 = str(tag0).replace('{', '')
            tag0 = tag0.replace('\'', '')
            tag0 = tag0.replace('tag', '')
            tag0 = tag0.replace('}', '')
            tag0 = tag0.replace(':', '')
            tag1 = data["tags"][1]            
            tag1 = str(tag1).replace('{', '')
            tag1 = tag1.replace('\'', '')
            tag1 = tag1.replace('tag', '')
            tag1 = tag1.replace('}', '')
            tag1 = tag1.replace(':', '')
            print ('[*] Sample upload time: ' + upload_time)
            print ('[*] Sample file type: ' + file_type)
            print ('[*] Sample tag: ' + tag0.strip())
            print ('[*] Sample tag: ' + tag1.strip())
            if (POE.logging == True):
                newlogentry = 'Sample upload time: ' + upload_time
                LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
                newlogentry = 'Sample file type: ' + file_type
                LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry) 
                newlogentry = 'Sample tag: ' + tag0.strip()
                LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
                newlogentry = 'Sample tag: ' + tag1.strip()
                LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)    
    except Exception as e:
        print (colored('[x] Error: ' + str(e) + ' Terminating...', 'red', attrs=['bold']))
        read_file.close()
        return -1
    #Clean up before returning    
    read_file.close()

    return 0
