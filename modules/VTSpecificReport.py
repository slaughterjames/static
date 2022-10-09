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
Type: Triage - Description: Retrieves data for a target against the VirusTotal database specifically for the Fortinet, Kaspersky and Microsoft A/V engines.
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
        newlogentry = 'Module: VTSpecificReport'           
        LOG.WriteStrongLog(POE.logdir, POE.targetfilename, newlogentry)

    for apikeys in POE.apikeys: 
        for key, value in apikeys.items():
            if (POE.debug == True):
                print ('[DEBUG] API: ' + str(key) + ' | API Key: ' + str(value))
            if (key == 'virustotal'):
                print ('[*] API key located!')
                apikey = value

    if (apikey == ''):
        print (colored('\r\n[x] Unable to execute VTSpecificReport - apikey value not input.  Please add one to /opt/static/static.conf', 'red', attrs=['bold']))
        if (logging == True):
            newlogentry = 'Unable to execute VTSpecificReport - apikey value not input.  Please add one to /opt/static/static.conf'
            LOG.WriteStrongSubLog(POE.logdir, POE.targetfilename, newlogentry)
            POE.csv_line += 'N/A,'
        return -1

    global json
    suggested_threat_label = ''
    kaspersky_category = ''
    kaspersky_engine_name = ''
    kaspersky_engine_version = ''
    kaspersky_result = ''
    kaspersky_method = ''
    kaspersky_engine_update = ''
    fortinet_category = ''
    fortinet_engine_name = ''
    fortinet_engine_version = ''
    fortinet_result = ''
    fortinet_method = ''
    fortinet_engine_update = ''
    microsoft_category = ''
    microsoft_engine_name = ''
    microsoft_engine_version = ''
    microsoft_result = ''
    microsoft_method = ''
    microsoft_engine_update = ''
    microsoft = ''
    output = POE.logdir + 'VTSpecificReport.json'

    FI = fileio()
    
    print (colored('[*] Running VTSpecificReport against: ' + POE.target, 'white', attrs=['bold']))

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
                print (colored('[*] VirusTotal malware report data had been written to file here: ', 'green') + colored(output, 'blue', attrs=['bold']))
                if (POE.logging == True):
                    if (POE.nolinksummary == False):
                        newlogentry = 'VirusTotal malware report data has been generated to file here: <a href=\"' + output + '\"> VirusTotal Malware Report </a>'           
                        LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
            except:
                print (colored('[x] Unable to write VirusTotal malware report data to file', 'red', attrs=['bold']))
                if (POE.logging == True):
                    newlogentry = 'Unable to write VirusTotal malware report data to file'
                    LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
                return -1

            result = json.loads(result)
            try:
                suggested_threat_label = result['data']['attributes']['popular_threat_classification']['suggested_threat_label']
            except:
                print ('[x] popular_threat_classification is not available...')
                suggested_threat_label = 'N/A'
            fortinet_category = result['data']['attributes']['last_analysis_results']['Fortinet']['category']
            fortinet_engine_name = result['data']['attributes']['last_analysis_results']['Fortinet']['engine_name']
            fortinet_engine_version = result['data']['attributes']['last_analysis_results']['Fortinet']['engine_version']
            fortinet_result = result['data']['attributes']['last_analysis_results']['Fortinet']['result']
            fortinet_method = result['data']['attributes']['last_analysis_results']['Fortinet']['method']
            fortinet_engine_update = result['data']['attributes']['last_analysis_results']['Fortinet']['engine_update']
            microsoft_category = result['data']['attributes']['last_analysis_results']['Microsoft']['category']
            microsoft_engine_name = result['data']['attributes']['last_analysis_results']['Microsoft']['engine_name']
            microsoft_engine_version = result['data']['attributes']['last_analysis_results']['Microsoft']['engine_version']
            microsoft_result = result['data']['attributes']['last_analysis_results']['Microsoft']['result']
            microsoft_method = result['data']['attributes']['last_analysis_results']['Microsoft']['method']
            microsoft_engine_update = result['data']['attributes']['last_analysis_results']['Microsoft']['engine_update']
            kaspersky_category = result['data']['attributes']['last_analysis_results']['Kaspersky']['category']
            kaspersky_engine_name = result['data']['attributes']['last_analysis_results']['Kaspersky']['engine_name']
            kaspersky_engine_version = result['data']['attributes']['last_analysis_results']['Kaspersky']['engine_version']
            kaspersky_result = result['data']['attributes']['last_analysis_results']['Kaspersky']['result']
            kaspersky_method = result['data']['attributes']['last_analysis_results']['Kaspersky']['method']
            kaspersky_engine_update = result['data']['attributes']['last_analysis_results']['Kaspersky']['engine_update']
            print ('[*] VirusTotal suggested threat label: ' + suggested_threat_label)
            newlogentry = 'VirusTotal suggested threat label: ' + suggested_threat_label
            LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
            print (colored('[*] VirusTotal Specific A/V Engine Results: ', 'green', attrs=['bold']))
            print ('[-] Fortinet Category: ' + fortinet_category)
            newlogentry = 'Fortinet Category: ' + fortinet_category
            LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
            print ('[-] Fortinet Engine Name: ' + fortinet_engine_name)
            newlogentry = 'Fortinet Engine Name: ' + fortinet_engine_name
            LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
            print ('[-] Fortinet Engine Version: ' + fortinet_engine_version)
            newlogentry = 'Fortinet Engine Version: ' + fortinet_engine_version
            LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
            print ('[-] Fortinet Result: ' + fortinet_result)
            newlogentry = 'Fortinet Result: ' + fortinet_result
            LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
            print ('[-] Fortinet Method: ' + fortinet_method)
            newlogentry = 'Fortinet Method: ' + fortinet_method
            LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
            print ('[-] Fortinet Engine Update: ' + fortinet_engine_update)
            newlogentry = 'Fortinet Engine Update: ' + fortinet_engine_update
            LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
            print ('[-] Microsoft Category: ' + microsoft_category)
            newlogentry = 'Microsoft Category: ' + microsoft_category
            LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
            print ('[-] Microsoft Engine Name: ' + microsoft_engine_name)
            newlogentry = 'Microsoft Engine Name: ' + microsoft_engine_name
            LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
            print ('[-] Microsoft Engine Version: ' + microsoft_engine_version)
            newlogentry = 'Microsoft Engine Version: ' + microsoft_engine_version
            LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
            print ('[-] Microsoft Result: ' + microsoft_result)
            newlogentry = 'Microsoft Result: ' + microsoft_result
            LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
            print ('[-] Microsoft Method: ' + microsoft_method)
            newlogentry = 'Microsoft Method: ' + microsoft_method
            LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
            print ('[-] Microsoft Engine Update: ' + microsoft_engine_update)
            newlogentry = 'Microsoft Engine Update: ' + microsoft_engine_update
            LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
            print ('[-] Kaspersky Category: ' + kaspersky_category)
            newlogentry = 'Kaspersky Category: ' + kaspersky_category
            LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
            print ('[-] Kaspersky Engine Name: ' + kaspersky_engine_name)
            newlogentry = 'Kaspersky Engine Name: ' + kaspersky_engine_name
            LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
            print ('[-] Kaspersky Engine Version: ' + kaspersky_engine_version)
            newlogentry = 'Kaspersky Engine Version: ' + kaspersky_engine_version
            LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
            print ('[-] Kaspersky Result: ' + kaspersky_result)
            newlogentry = 'Kaspersky Result: ' + kaspersky_result
            LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
            print ('[-] Kaspersky Method: ' + kaspersky_method)
            newlogentry = 'Kaspersky Method: ' + kaspersky_method
            LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
            print ('[-] Kaspersky Engine Update: ' + kaspersky_engine_update)
            newlogentry = 'Kaspersky Engine Update: ' + kaspersky_engine_update
            LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)

        else:
            print (colored('[x] HTTP Error [' + str(vt_api_files.get_last_http_error()) +']', 'red', attrs=['bold']))
            newlogentry = 'HTTP Error [' + str(vt_api_files.get_last_http_error()) +']'
            LOG.WriteStrongSubLog(POE.logdir, POE.targetfilename, newlogentry)  

    return 0
