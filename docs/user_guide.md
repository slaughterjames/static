## Static v0.3 - User Guide

----

## Simple Examples For Getting Started

The Static help screen can be shown by typing the following:

```bash
/opt/static/static.py --help
```

All flags must be preceded by 2 hyphens "--".

Typical parameters for exploring an external host without touching it directly:

```bash
/opt/static/static.py --target example.exe --type "triage pe" --modules all
```
This will execute the tool against example.exe and run all modules that have been identified in the conf file as "triage" and "pe".

## Command-line Usage Information

Static has several command-line flags which are described below. - ToDo

| Flag | Description |
|------------|-------------|
| --target OR --targetfolder | Required - Investigate a single file or entire folder of them (NOTE!!! Must be of the same type!!!) |
| --type | Required - triage, search, pe, elf, office, lnk. --triage can be used with every type except search by enclosing the statement in quotes "". |
| --modules | Required - All or Specific - What specific modules to use or all of them for a particular type. |
| --hash    | Optional - MD5, SHA1 or SHA256 hash to use with --type search function. |
| --force | Optional - Force analysis type even if the header details don't match. |
| --sleeptime | Optional - The number of seconds paused between targets. |
| --output | Optional - Put the output of the tool in a specific directory. |
| --nolinksummary | Optional - Leave out links in the summary file to keep it clean and simple. |
| --listmodules | Optional - Prints a list of available modules and their descriptions. |
| --listaddintypes | Optional - Prints a list of available addin types as defined in the mirage.conf file.  Defines a group of modules to run. |
| --listapikeys | Optional - Prints a list of available API Keys. |
| --debug | Optional - Prints verbose logging to the screen to troubleshoot issues with a Static installation.|
| --help | Optional - Prints list of flags |

## Default Modules

The modules that come standard with Static are as follows:

| Module | Type | Description |
|------|-------------|---------|
| VTMalwareReport | Triage | Description: Retrieves any available data for a target against the VirusTotal database. | 
| VTSpecificReport | Triage | Description: Retrieves data for a target against the VirusTotal database specifically for the Fortinet, Kaspersky and Microsoft A/V engines. | 
| IntezerReport | Triage | Description: Retrieves any available data for a target against the Intezer database. | 
| malware_bazaar | Triage | Description: Retrieves any available data for a target against the Abuse.ch Malware Bazaar database. | 
| CERTPL | Triage | Description: Retrieves any available data on a target against the CERT.PL malware database. | 
| yara | Triage | Description: Runs Yara rules against the sample. | 
| reademail | Email | Description: Reads an eml or msg file and outputs the contents. | 
| staticpe | PE | Description: Uses PEUtils to get the particulars on the submitted sample to give a jump start on reverse engineering. | 
| readelf | Elf | Description: Uses readelf to pull the header information from an ELF file. | 
| objdump | Elf | Description: Dumps all headers, disassembled data from an ELF file using objdump. | 
| extractmacro | Office | Description: Uses olevba to extract any macro code from a Microsoft Office file. | 
| extractoleobj | Office | Description: Uses olevba to extract any ole object from a Microsoft Office file. | 
| oledump | Office | Description: Uses oledump to extract any ole object from a Microsoft Office file. | 
| rtfdump | Office | Description: Uses rtfdump to extract any ole object data from a Microsoft RTF file. | 
| vipermonkey | Office | Description: Runs Vipermonkey against an office sample. | 
| VTSearch | Search | Description: Retrieves any available data for a target against the VirusTotal database. | 
| malware_bazaar_search | Search | Description: Searches for any available data on a target against the Abuse.ch Malware Bazaar database. | 
| XForceSearch | Search | Description: Retrieves any available data for a target against the IBM XForce database. | 
| IntezerSearch | Search | Description: Retrieves any available data for a target against the Intezer database. | 
| CERTPL_search | Triage | Description: Searches for any available data on a target against the CERT.PL malware database. | 
| lnkdump | Office | Description: Uses lnkinfo to extract data from a Microsoft Windows Shortcut file. | 
| VTFetch | Search | Description: Retrieves a target file from the VirusTotal database. | 

### The config file

The Static config file contains settings for how the tool behaves and what modules to run.  To access, open the following file:

```bash
sudo nano /opt/static/static.conf
```

The file is structured for JSON and settings are in the format of "setting":"value",.  The quotes are required as is the comma at the end.  The defaults settings are described below: 

| Setting | Description | - ToDo
|------------|-------------|
| "logger" | true or false - Determines whether built in logging is used.  If false, output will still be directed to the console |
| "logroot" | directory - If the above option is true, this will be the directory where default output is logged.  Remember the trailing "/" at the end of the directory |
| "modulesdir" | directory - Directory where modules are stored.  By default it's /opt/mirage/modules/.   |
| "useragent" | Browser user-agent string for any modules that require web-based contact.  "default" by default |
| "sleeptime" | Time to wait between targets.  7 seconds by default. |
| "addintypes" | "triage","office","pe","elf","search" are the default module types.  |
| "addins" | These are the actual modules |

The config file in its entirety is:

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

### Running

There are multiple ways to explore a target.  

To access a single module, run the following:

```bash
/opt/static/static.py --target example.doc --type office --modules extractmacro
```

To direct output to a specific location:

```bash
opt/static/static.py --target example.doc --type office --modules all --output /home/yourname/yourdirectory
```

To review multiple files in a single folder:

```bash
/opt/static/static.py --targetfolder /home/scalp/hopper --type office --modules all --output /home/scalp/staticlogs3/test
```

Output to the console will look like the following: -ToDo

```bash
$ /opt/static/static.py --target /home/scalp/hopper/FILE_2020.doc --type office --modules all 
[*] Length Arguments: 7
[*] Arguments: 
target: /home/scalp/hopper/FILE_2020.doc
type: office
modules: all
[*] Type is office
[*] Logger is active
[*] Creating log file

[*] Beginning file triage... 
[*] Filesize is: 161555 bytes.
[*] MD5 hash of file : b0f3dee70aa014d8103bd886a60049bc
[*] SHA1 hash of file : c9a862eede698a66d331e6803a7811e3d77e446c
[*] SHA256 hash of file : d698f44817a8dd148ce4e4f792b165308846d21d0ecccce11d06e9fccabaf868
[*] If a VirusTotal record exists, it will be located here: https://www.virustotal.com/en/file/d698f44817a8dd148ce4e4f792b165308846d21d0ecccce11d06e9fccabaf868/analysis/
[*] File extension: doc
[*] File type: /home/scalp/hopper/FILE_2020.doc:  Composite Document File V2 Document, Little Endian, Os: Windows, Version 6.2, Code page: 1252, Subject: platforms District withdrawal monitor Auto Loan Account Plains compelling Movies, Grocery & Books multi-byte Implementation, Author: Lilou Leroux, Template: Normal.dotm, Last Saved By: Maxime Marty, Revision Number: 1, Name of Creating Application: Microsoft Office Word, Create Time/Date: Tue Dec 29 13:35:00 2020, Last Saved Time/Date: Tue Dec 29 13:36:00 2020, Number of Pages: 1, Number of Words: 2202, Number of Characters: 12554, Security: 8\n'
[*] Exif data had been written to file here: /home/scalp/staticlogs2/FILE_2020.doc/exif.txt
[-] Reading Exif file: /home/scalp/staticlogs2/FILE_2020.doc/exif.txt
[*] File Type                       : DOC

[*] File Type Extension             : doc

[*] MIME Type                       : application/msword

[*] Software                        : Microsoft Office Word

[*] Comp Obj User Type Len          : 39

[*] Comp Obj User Type              : Microsoft Office Word 97-2003 Document

[*] Strings data had been written to file here: /home/scalp/staticlogs2/FILE_2020.doc/strings.txt

[-] Organize Modules...
pywin32 is not installed (only is required if you want to use MS Excel)

[*] Running extractmacro against: /home/scalp/hopper/FILE_2020.doc
[-] VBA macros found - Extracting...
[*] Macro Xlb0g5eyj545.cls extracted to: /home/scalp/staticlogs2/FILE_2020.doc/Xlb0g5eyj545.cls
[*] Macro Bt08uhxu1tnhy1.bas extracted to: /home/scalp/staticlogs2/FILE_2020.doc/Bt08uhxu1tnhy1.bas
[*] Macro Xhlj9irufb65_wekzf.bas extracted to: /home/scalp/staticlogs2/FILE_2020.doc/Xhlj9irufb65_wekzf.bas

[*] Running vipermonkey against: /home/scalp/hopper/FILE_2020.doc
[*] vipermonkey data has been generated to file here: /home/scalp/staticlogs2/FILE_2020.doc/vmonkey.txt

[*] Summary file written to: /home/scalp/staticlogs2/FILE_2020.doc/FILE_2020.doc.html

[*] Program Complete
```

When logging is enabled, it will be deposited into a subdirectory that has the target's file name.  There will be an HTML file that will have a summary as well as hyperlinks to each log file.

### Creating additional modules

In the Static directory, there is an example template for a new module to be created.  To access:

```bash
nano /opt/static/example_module.py
```

This file contains instructions on how to get your module working.  It will need to be deposited into the modules subdirectory and an entry will need to be added to the Static config file under the addins setting.
