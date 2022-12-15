#python imports
import sys
import os
import subprocess
import json
from requests import get
from termcolor import colored
from vtapi3 import VirusTotalAPIFiles, VirusTotalAPIError

#third-party imports
#from vtapi3 import VirusTotalAPIFiles, VirusTotalAPIErrors

#programmer generated imports
from logger import logger
from fileio import fileio

'''
***BEGIN DESCRIPTION***
Type: Search - Description: Retrieves a target file from the VirusTotal database.
***END DESCRIPTION***
'''
def POE(POE):

    apikey = ''

    if (POE.logging == True): 
        LOG = logger() 
    newlogentry = ''

    if (POE.logging == True):
        newlogentry = 'Module: VTFetch'           
        LOG.WriteStrongLog(POE.logdir, POE.targetfilename, newlogentry)

    if (POE.SHA256 == ''):
        print (colored('\r\n[x] Unable to execute VTFetch - hash value must be SHA256.', 'red', attrs=['bold']))
        newlogentry = 'Unable to execute VTFetch - hash value must be SHA256'
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
        print (colored('\r\n[x] Unable to execute VTFetch - apikey value not input.  Please add one to /opt/static/static.conf', 'red', attrs=['bold']))
        if (logging == True):
            newlogentry = 'Unable to execute VTFetch - apikey value not input.  Please add one to /opt/static/static.conf'
            LOG.WriteStrongSubLog(POE.logdir, POE.targetfilename, newlogentry)
            POE.csv_line += 'N/A,'
        return -1

    global json
    file_extension = ''
    file_name = ''
    searchoutput = POE.logdir + 'VTSearchReport.json'

    FI = fileio()
    
    print (colored('[*] Running VTFetch against: ' + POE.target, 'white', attrs=['bold']))


    print (colored('[*] Pulling VT report for: ' + POE.target, 'white', attrs=['bold']))

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
                FI.WriteLogFile(searchoutput, result)
                print (colored('[*] VirusTotal search report data had been written to file here: ', 'green') + colored(searchoutput, 'blue', attrs=['bold']))
                if (POE.logging == True):
                    if (POE.nolinksummary == False):
                        newlogentry = 'VirusTotal search report data has been generated to file here: <a href=\"' + searchoutput + '\"> VirusTotal Search Report </a>'           
                        LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
            except:
                print (colored('[x] Unable to write VirusTotal search report data to file', 'red', attrs=['bold']))
                if (POE.logging == True):
                    newlogentry = 'Unable to write VirusTotal search report data to file'
                    LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
                return -1

            result = json.loads(result)
            try:
                suggested_threat_label = result['data']['attributes']['popular_threat_classification']['suggested_threat_label']
            except:
                print ('[x] popular_threat_classification is not available...')
                suggested_threat_label = 'N/A'
            try:
                fortinet_result = result['data']['attributes']['last_analysis_results']['Fortinet']['result']
            except:
                print ('[x] fortinet_result is not available...')
                fortinet_result = 'N/A'
            file_extension = result['data']['attributes']['type_extension']
            harmless = result['data']['attributes']['last_analysis_stats']['harmless']
            undetected = result['data']['attributes']['last_analysis_stats']['undetected']
            suspicious  = result['data']['attributes']['last_analysis_stats']['suspicious']
            malicious = result['data']['attributes']['last_analysis_stats']['malicious']
            meaningful_name = result['data']['attributes']['meaningful_name']
            try:
                print ('[*] VirusTotal meaningful name: ' + meaningful_name)
                newlogentry = 'VirusTotal meaningful name: ' + meaningful_name
                LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
            except:
                print ('[*] VirusTotal meaningful name: N/A')
                newlogentry = 'VirusTotal meaningful name: N/A'
                LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)                
            print ('[*] VirusTotal suggested threat label: ' + suggested_threat_label)
            newlogentry = 'VirusTotal suggested threat label: ' + suggested_threat_label
            LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
            print ('[-] Fortinet threat label: ' + fortinet_result)
            newlogentry = 'Fortinet threat label: ' + fortinet_result
            LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
            print (colored('[*] VirusTotal A/V engine results: ', 'green', attrs=['bold']))
            print ('[-] Number of A/V engines marking sample as harmless: ' + str(harmless))
            newlogentry = 'Number of A/V engines marking sample as harmless: ' + str(harmless)
            LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
            print ('[-] Number of A/V engines not detecting sample: ' + str(undetected))
            newlogentry = 'Number of A/V engines not detecting sample: ' + str(undetected)
            LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
            print ('[-] Number of A/V engines marking sample as suspicious: ' + str(suspicious))
            newlogentry = 'Number of A/V engines marking sample as suspicious: ' + str(suspicious)
            LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
            print ('[-] Number of A/V engines marking sample as malicious: ' + str(malicious))
            newlogentry = 'Number of A/V engines marking sample as malicious: ' + str(malicious)
            LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
        else:
            print (colored('[x] HTTP Error [' + str(vt_api_files.get_last_http_error()) +']', 'red', attrs=['bold']))
            newlogentry = 'HTTP Error [' + str(vt_api_files.get_last_http_error()) +']'
            LOG.WriteStrongSubLog(POE.logdir, POE.targetfilename, newlogentry)

    output = POE.logdir + POE.target + '.' + str(file_extension)
    vt = 'https://www.virustotal.com/api/v3/files/' + POE.target.strip() + '/download'
    headers = ({'x-apikey': apikey.strip()})

    try:
        with open(output, "wb") as file:
            # get request
            response = get(vt,headers=headers)
            # write to file
            file.write(response.content)
            print (colored('[*] VTFetch has generated file here: ', 'green') + colored(output, 'blue', attrs=['bold']))
            if (POE.logging == True):
                if (POE.nolinksummary == False):
                    newlogentry = 'VTFetch has generated file to here: <a href=\"' + output + '\"> '+ POE.target + ' </a>'           
                    LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
    except Exception as e:
        print ('[x] Unable to retrieve file!  Terminating... ', e)
        if (POE.logging == True):
            newlogentry = 'Unable to retrieve file!  Terminating... ', e           
            LOG.WriteStrongSubLog(POE.logdir, POE.targetfilename, newlogentry)
        return -1
     

    return 0
