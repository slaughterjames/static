#python imports
import sys
import os
import subprocess
import json
import time
import requests
from termcolor import colored

#third-party imports
#No third-party imports

#programmer generated imports
from logger import logger
from fileio import fileio

'''
***BEGIN DESCRIPTION***
Type: Triage - Description: Retrieves any available data for a target against the Intezer database.
***END DESCRIPTION***
'''
def POE(POE):

    apikey = ''

    if (POE.logging == True): 
        LOG = logger() 
    newlogentry = ''
    reputation_dump = ''
    reputation_output_data = ''
    whois = ''

    if (POE.logging == True):
        newlogentry = 'Module: IntezerReport'           
        LOG.WriteStrongLog(POE.logdir, POE.targetfilename, newlogentry)

    for apikeys in POE.apikeys: 
        for key, value in apikeys.items():
            if (POE.debug == True):
                print ('[DEBUG] API: ' + str(key) + ' | API Key: ' + str(value))
            if (key == 'intezer'):
                print ('[*] API key located!')
                apikey = value

    if (apikey == ''):
        print (colored('\r\n[x] Unable to execute IntezerReport - apikey value not input.  Please add one to /opt/static/static.conf', 'red', attrs=['bold']))
        if (logging == True):
            newlogentry = 'Unable to execute IntezerReport - apikey value not input.  Please add one to /opt/static/static.conf'
            LOG.WriteStrongSubLog(POE.logdir, POE.targetfilename, newlogentry)
            POE.csv_line += 'N/A,'
        return -1

    global json
    output = POE.logdir + 'IntezerReport.json'
    analysis_time = ''
    analysis_url = ''
    family_name = ''
    verdict = ''

    FI = fileio()
    
    print (colored('\r\n[*] Running IntezerReport against: ' + POE.target, 'white', attrs=['bold']))

    intezer_url = 'https://analyze.intezer.com/api/v2-0'
    result_url = '/files/' + POE.SHA256
    response = requests.post(intezer_url + '/get-access-token', json={'api_key': apikey})
    response.raise_for_status()
    session = requests.session()
    session.headers['Authorization'] = session.headers['Authorization'] = 'Bearer %s' % response.json()['result']

    try:
        response = session.get(intezer_url + result_url)
        response.raise_for_status()
    except:
        print ('[-] Intezer exception raised...')

    if (response.status_code == 200):
        print ('[*] Response 200 from server...')
        result = response.json()
        result = json.dumps(result, sort_keys=False, indent=4)
        if (POE.debug==True):
            print(str(result))
        try:
            FI.WriteLogFile(output, result)
            print (colored('[*] Intezer malware report data had been written to file here: ', 'green') + colored(output, 'blue', attrs=['bold']))
            if (POE.logging == True):
                if (POE.nolinksummary == False):
                    newlogentry = 'Intezer malware report data has been generated to file here: <a href=\"' + output + '\"> Intezer Summary </a>'           
                    LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
        except:
            print (colored('[x] Unable to write Intezer malware report data to file', 'red', attrs=['bold']))
            if (POE.logging == True):
                newlogentry = 'Unable to write Intezer malware report data to file'
                LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
                return -1
            
        result = json.loads(result)

        analysis_url = result['result']['analysis_url']
        print ('[*] Intezer analysis URL: ' + analysis_url)
        newlogentry = 'Intezer analysis URL: ' + analysis_url
        LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
        analysis_time = result['result']['analysis_time']
        print ('[*] Intezer analysis time: ' + analysis_time)
        newlogentry = 'Intezer analysis time: ' + analysis_time
        LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
        try:
            family_name = result['result']['family_name']
            print ('[*] Intezer malware family designation: ' + family_name)
            newlogentry = 'Intezer malware family designation: ' + family_name
            LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
        except:
            print ('[-] Intezer malware family designation unavailable! ')
            newlogentry = 'Intezer malware family designation unavailable! '
            LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
        verdict = result['result']['verdict']
        print ('[*] Intezer verdict: ' + verdict)
        newlogentry = 'Intezer verdict: ' + verdict
        LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)

    else:
        print ('[-] Intezer response HTTP status code: ' + str(response.status_code))
        print (colored('[-] Unable to locate sample...', 'yellow', attrs=['bold']))
        newlogentry = 'Unable to locate sample...'
        LOG.WriteStrongSubLog(POE.logdir, POE.targetfilename, newlogentry)  

    return 0
