## Static v0.3

Static is a tool designed to help perform the initial triage of a potentially malicious file.  With modularity built-in to the tool, it is easy to create new modules quickly to solve new and unforseen problems in obtaining information.

**Pre-built Modules:**

* **[*] VTMalwareReport:** Type: Triage - Description: Retrieves any available data for a target against the VirusTotal database.
* **[*] VTSpecificReport:** Type: Triage - Description: Retrieves data for a target against the VirusTotal database specifically for the Fortinet, Kaspersky and Microsoft A/V engines.
* **[*] IntezerReport:** Type: Triage - Description: Retrieves any available data for a target against the Intezer database.
* **[*] malware_bazaar:** Type: Triage - Description: Retrieves any available data for a target against the Abuse.ch Malware Bazaar database.
* **[*] CERTPL:** Type: Triage - Description: Retrieves any available data on a target against the CERT.PL malware database.
* **[*] yara:** Type: Triage - Description: Runs Yara rules against the sample.
* **[*] reademail:** Type: Email - Description: Reads an eml or msg file and outputs the contents.
* **[*] staticpe:** Type: PE - Description: Uses PEUtils to get the particulars on the submitted sample to give a jump start on reverse engineering.
* **[*] readelf:** Type: Elf - Description: Uses readelf to pull the header information from an ELF file.
* **[*] objdump:** Type: Elf - Description: Dumps all headers, disassembled data from an ELF file using objdump.
* **[*] extractmacro:** Type: Office - Description: Uses olevba to extract any macro code from a Microsoft Office file.
* **[*] extractoleobj:** Type: Office - Description: Uses olevba to extract any ole object from a Microsoft Office file.
* **[*] oledump: Type:** Office - Description: Uses oledump to extract any ole object from a Microsoft Office file.
* **[*] rtfdump: Type:** Office - Description: Uses rtfdump to extract any ole object data from a Microsoft RTF file.
* **[*] vipermonkey:** Type: Office - Description: Runs Vipermonkey against an office sample.
* **[*] VTSearch: Type:** Search - Description: Retrieves any available data for a target against the VirusTotal database.
* **[*] malware_bazaar_search:** Type: Search - Description: Searches for any available data on a target against the Abuse.ch Malware Bazaar database.
* **[*] XForceSearch:** Type: Search - Description: Retrieves any available data for a target against the IBM XForce database.
* **[*] IntezerSearch:** Type: Search - Description: Retrieves any available data for a target against the Intezer database.
* **[*] CERTPL_search:** Type: Triage - Description: Searches for any available data on a target against the CERT.PL malware database.
* **[*] lnkdump:** Type: Office - Description: Uses lnkinfo to extract data from a Microsoft Windows Shortcut file.
* **[*] VTFetch:** Type: Search - Description: Retrieves a target file from the VirusTotal database
 
----

## Documentation

Use the [Installation Guide](https://github.com/slaughterjames/static/blob/main/doc/install.md) to get started. - ToDo

Go to the [User's Guide](https://github.com/slaughterjames/static/blob/main/doc/user_guide.md) for additional information. -ToDo
