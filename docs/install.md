## Static v0.3 - Installation Guide

Static has been tested on Ubuntu-based Linux distributions.  It is generally recommended using the the latest available version (or at least the latest long-term supported version).  The majority of the code is written in Python3.

## Download the Installation Script

1. Download the Static installation script:
```bash
wget https://raw.githubusercontent.com/slaughterjames/static/main/get-static.sh
```
2. Grant execution privileges:
```
chmod 755 get-static.sh
```

## Execute the Script

1. Execute the script:

```bash
sudo ./get-static.sh
```

The script will do the heavy lifting of installing the requisite .deb files and Python libraries as well as tucking the program files into the correct directory.

## Test for Failed Installation of Python Libraries

Occasionally, pip doesn't install all of the Python modules for one reason or another.  To test everything was installed, simply try to execute Static:

```bash
/opt/static/static.py
```

If there were issues executing the install of the modules, it will turn up here.  To fix, run the following:

```bash
sudo pip3 install <required python library>
```

## Updating the static.conf File

The static.conf file contains the configuration information used by Stati to execute.  It needs a few values up front in order to execute.

1. Use your favourite editor to open the static.conf file.  We'll use nano in this example:

```bash
nano /opt/static/static.conf
```

2. Review default settings:

```bash
{
    "logger": "true",
    "logroot": "<add your log directory>",
    "modulesdir": "/opt/scalp/static/modules/",
    "yararulesdirectory": "/opt/static/yara/",
    "sleeptime": "7",
    "useragent": "default",
    "apikeys": [
        {
            "virustotal": ""
        },
        {
            "intezer": ""
        },
        {
            "xforceapi": ""
        },
        {
            "xforcepassword": ""
        }
    ],
    "addintypes": ["triage","office","pe","elf","search","fetch","lnk"],
    "addins": [
        {
            "triage": "VTMalwareReport"
        },
        {
            "triage": "IntezerReport"
        },
        {
            "triage": "malware_bazaar"
        },
        {
            "triage": "yara"
        },
        {
            "pe": "staticpe"
        },
        {
            "elf": "readelf"
        },
        {
            "elf": "objdump"
        },
        {
            "office": "extractmacro"
        },
        {
            "office": "vipermonkey"
        },
        {
            "search": "VTSearch"
        },
        {
            "search": "malware_bazaar_search"
        },
        {
            "search": "XForceSearch"
        },
        {
            "search": "IntezerSearch"
        },
        {
            "lnk": "lnkdump" 
        },
        {
            "fetch": "VTFetch"
        }
    ]
}

```

You'll note the conf file is structured into JSON, so carefully note the placement of brackets, quotes and commas when editing.

3. If you don't wish to use logging and rely on the screen output, modify this line:

```bash
    "logger": "true",
```
Change "true" to "false"

4. If you'd to use logging, modify this line:

```bash
    "logroot": "<add your log directory>",
```

Replace <add your log directory> with your desired log location and remember to include a "/" (without the quotes) as the last character.


## Static Modules With API Keys - ToDo

Three pre-built Static modules require API keys from the organizations supplying the data.  These are the VirusTotal, IBM X-Force and Intezer modules.  Accounts with each both organization are free and come out of the box with API access which can be obtained here for [VirusTotal](https://www.virustotal.com/gui/join-us), here for [IBM X-Force](https://www.ibm.com/security/xforce) and here for [Intezer](https://analyze.intezer.com/create-account).

1. To add your API keys, edit the static.conf file with the following command:  

```bash
nano /opt/static/static.conf
```

2. Where you see the following lines, add your keys inside of the " ":

```bash
    "apikeys": [
        {
            "virustotal": ""
        },
        {
            "intezer": ""
        },
        {
            "xforceapi": ""
        },
        {
            "xforcepassword": ""
        }
```
