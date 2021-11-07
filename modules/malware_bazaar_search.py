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
Type: Search - Description: Searches for any available data on a target against the Abuse.ch Malware Bazaar database.
***END DESCRIPTION***
'''
def POE(POE):

    if (POE.logging == True): 
        LOG = logger() 
    newlogentry = ''
    reputation_dump = ''
    reputation_output_data = ''
    malwarebazaar = ''

    if (POE.logging == True):
        newlogentry = 'Module: malware_bazaar_search'           
        LOG.WriteStrongLog(POE.logdir, POE.targetfilename, newlogentry)

    if (POE.SHA256 == ''):
        print (colored('\r\n[x] Unable to execute Malware Bazaar Search - hash value must be SHA256.', 'red', attrs=['bold']))
        newlogentry = 'Unable to execute Malware Bazaar Search  - hash value must be SHA256'
        LOG.WriteStrongSubLog(POE.logdir, POE.targetfilename, newlogentry)
        return -1

    global json
    query_status = ''
    first_seen = ''
    last_seen = ''
    signature = ''
    sig_count = 0
    output = POE.logdir + 'MalwareBazaarSearch.json'

    FI = fileio()

    print (colored('\r\n[*] Running abuse.ch Malware Bazaar Search against: ' + POE.target, 'white', attrs=['bold']))

    malwarebazaar = "https://mb-api.abuse.ch/api/v1/" #API URL
    data = { #Our header params
      'query': 'get_info',
      'hash': POE.SHA256,
    }

    response_dump = requests.post(malwarebazaar, data=data, timeout=15) # Give us the results as JSON

    if (POE.debug == True):
        print (response_dump)

    try:        
        FI.WriteLogFile(output, response_dump.content.decode("utf-8", "ignore"))
        print (colored('[*] Malware Bazaar data had been written to file here: ', 'green') + colored(output, 'blue', attrs=['bold']))
        if ((POE.logging == True) and (POE.nolinksummary == False)):
            newlogentry = 'Malware Bazaar data has been generated to file here: <a href=\"' + output + '\"> Malware Bazaar Host Output </a>'           
            LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
    except:
        print (colored('[x] Unable to write Malware Bazaar data to file', 'red', attrs=['bold']))
        if (POE.logging == True):
            newlogentry = 'Unable to write Malware Bazaar data to file'
            LOG.WriteStrongSubLog(POE.logdir, POE.targetfilename, newlogentry)
            POE.csv_line += 'N/A,'
        return -1

    try:
        #Open the file we just downloaded
        print ('[-] Reading Malware Bazaar file: ' + output.strip())

        with open(output.strip(), 'rb') as read_file:
            data = json.load(read_file, cls=None)
        read_file.close()

        # Check what kind of results we have
        query_status = data["query_status"]      
        print ('[*] query_status: ' + query_status)
        if (query_status == 'ok'):
            with open(output.strip(), 'r') as read_file:
                for string in read_file:
                    if (POE.debug == True):
                        print ('[DEBUG] string: ' + string.strip())
                    if ('first_seen' in string):
                        first_seen = string.strip()                    
                    if ('last_seen' in string):
                        last_seen = string.strip()
                    if (('signature' in string) and (sig_count == 0)):
                        signature = string.strip()
                        sig_count += 1
            print ('[*] Sample ' + first_seen.replace(',',''))
            print ('[*] Sample ' + last_seen.replace(',',''))
            print ('[*] Sample ' + signature.replace(',',''))
            if (POE.logging == True):
                newlogentry = 'Sample ' + first_seen.replace(',','')
                LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
                newlogentry = 'Sample ' + last_seen.replace(',','')
                LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry) 
                newlogentry = 'Sample ' + signature.replace(',','')
                LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
        #Can't find anything on this one... 
        elif (query_status == 'hash_not_found'):
            print (colored('[-] The hash value has not been found...', 'yellow', attrs=['bold']))
            if (POE.logging == True):
                newlogentry = 'No results available for host...'
                LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
        #Can't find anything on this one...
        elif (query_status == 'no_results'):
            print (colored('[-] No results available for host...', 'yellow', attrs=['bold']))
            if (POE.logging == True):
                newlogentry = 'No results available for host...'
                LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
        #Something weird happened...
        else:
            print (colored('[x] An error has occurred...', 'red', attrs=['bold']))
            if (POE.logging == True):
                newlogentry = 'An error has occurred...'
                LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)     
    except Exception as e:
        print (colored('[x] Error: ' + str(e) + ' Terminating...', 'red', attrs=['bold']))
        read_file.close()
        return -1
    #Clean up before returning    
    read_file.close()

    return 0
