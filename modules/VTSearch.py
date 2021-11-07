#python imports
import sys
import os
import subprocess
import json
from vtapi3 import VirusTotalAPIFiles, VirusTotalAPIError
from termcolor import colored

#third-party imports
#No third-party imports

#programmer generated imports
from logger import logger
from fileio import fileio

'''
***BEGIN DESCRIPTION***
Type: Search - Description: Retrieves any available data for a target against the VirusTotal database.
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
        newlogentry = 'Module: VTSearch'           
        LOG.WriteStrongLog(POE.logdir, POE.targetfilename, newlogentry)

    if (POE.SHA256 == ''):
        print (colored('\r\n[x] Unable to execute VTSearch - hash value must be SHA256.', 'red', attrs=['bold']))
        newlogentry = 'Unable to execute VTSearch  - hash value must be SHA256'
        LOG.WriteStrongSubLog(POE.logdir, POE.targetfilename, newlogentry)
        return -1

    for apikeys in POE.apikeys: 
        for key, value in apikeys.items():
            if (POE.debug == True):
                print ('[DEBUG] API: ' + str(key) + ' | API Key: ' + str(value))
            if (key == 'virustotal'):
                print ('\r\n[*] API key located!')
                apikey = value

    if (apikey == ''):
        print (colored('\r\n[x] Unable to execute VTSearch - apikey value not input.  Please add one to /opt/static/static.conf', 'red', attrs=['bold']))
        if (logging == True):
            newlogentry = 'Unable to execute VTSearch - apikey value not input.  Please add one to /opt/static/static.conf'
            LOG.WriteStrongSubLog(POE.logdir, POE.targetfilename, newlogentry)
            POE.csv_line += 'N/A,'
        return -1

    global json
    malware_flag = 0
    badware_flag = 0
    botnet_flag = 0
    infection_flag = 0
    suggested_threat_label = ''
    harmless = 0
    undetected = 0
    suspicious = 0
    malicious = 0
    output = POE.logdir + 'VTSearchReport.json'
    vtwhois_data = ''
    vtwhois_output_data = ''

    FI = fileio()
    
    print (colored('[*] Running VTSearch against: ' + POE.target, 'white', attrs=['bold']))

    vt_api_files = VirusTotalAPIFiles(apikey)

    try:
        result = vt_api_files.get_report(POE.SHA256)
    except VirusTotalAPIError as err:
        print(err, err.err_code)
    else:
        if (vt_api_files.get_last_http_error() == vt_api_files.HTTP_OK):
            result = json.loads(result)
            result = json.dumps(result, sort_keys=False, indent=4)
            if (POE.debug==True):
                print(result)
            try:
                FI.WriteLogFile(output, result)
                print (colored('[*] VirusTotal search report data had been written to file here: ', 'green') + colored(output, 'blue', attrs=['bold']))
                if (POE.logging == True):
                    if (POE.nolinksummary == False):
                        newlogentry = 'VirusTotal search report data has been generated to file here: <a href=\"' + output + '\"> VirusTotal Search Report </a>'           
                        LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
            except:
                print (colored('[x] Unable to write VirusTotal search report data to file', 'red', attrs=['bold']))
                if (POE.logging == True):
                    newlogentry = 'Unable to write VirusTotal search report data to file'
                    LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
                return -1

            result = json.loads(result)
            suggested_threat_label = result['data']['attributes']['popular_threat_classification']['suggested_threat_label']
            harmless = result['data']['attributes']['last_analysis_stats']['harmless']
            undetected = result['data']['attributes']['last_analysis_stats']['undetected']
            suspicious  = result['data']['attributes']['last_analysis_stats']['suspicious']
            malicious = result['data']['attributes']['last_analysis_stats']['malicious']
            print ('[*] VirusTotal suggested threat label: ' + suggested_threat_label)
            newlogentry = 'VirusTotal suggested threat label: ' + suggested_threat_label
            LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
            print (colored('[*] VirusTotal A/V engine results: ', 'green', attrs=['bold']))
            print ('[-] Number of A/V engines marking sample as harmless: ' + str(harmless))
            newlogentry = 'Number of A/V engines marking sample as harmless: ' + str(harmless)
            LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
            print ('[-] Number of A/V engines not detecting sample: ' + str(undetected))
            newlogentry = 'Number of A/V engines not detecting sample: ' + str(undetected)
            LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
            print ('[-] Number of A/V engines not marking sample as suspicious: ' + str(suspicious))
            newlogentry = 'Number of A/V engines not marking sample as suspicious: ' + str(suspicious)
            LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
            print ('[-] Number of A/V engines not marking sample as malicious: ' + str(malicious))
            newlogentry = 'Number of A/V engines not marking sample as malicious: ' + str(malicious)
            LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
        else:
            print (colored('[x] HTTP Error [' + str(vt_api_files.get_last_http_error()) +']', 'red', attrs=['bold']))
            newlogentry = 'HTTP Error [' + str(vt_api_files.get_last_http_error()) +']'
            LOG.WriteStrongSubLog(POE.logdir, POE.targetfilename, newlogentry)  

    return 0
