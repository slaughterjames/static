## Static v0.2

Static is a tool designed to help perform the initial triage of a potentially malicious file.  With modularity built-in to the tool, it is easy to create new modules quickly to solve new and unforseen problems in obtaining information.

**Pre-built Modules:**

* **[*] VTMalwareReport:** Type: Triage - Description: Retrieves any available data for a target against the VirusTotal database.
* **[*] IntezerReport:** Type: Triage - Description: Retrieves any available data for a target against the Intezer database.
* **[*] malware_bazaar:** Type: Triage - Description: Retrieves any available data for a target against the Abuse.ch Malware Bazaar database.
* **[*] yara:** Type: Triage - Description: Runs Yara rules against the sample.
* **[*] staticpe:** Type: PE - Description: Uses PEUtils to get the particulars on the submitted sample to give a jump start on reverse engineering.
* **[*] readelf:** Type: Elf - Description: Uses readelf to pull the header information from an ELF file.
* **[*] objdump:** Type: Elf - Description: Dumps all headers, disassembled data from an ELF file using objdump.
* **[*] extractmacro:** Type: Office - Description: Uses olevba to extract any macro code from a Microsoft Office file.
* **[*] vipermonkey:** Type: Office - Description: Runs Vipermonkey against an office sample.
* **[*] VTSearch:** Type: Info - Description: Executes a grep against the abuse.ch ransomware domains feed.
* **[*] malware_bazaar_search:** Search - Description: Searches for any available data on a target against the Abuse.ch Malware Bazaar database.
* **[*] XForceSearch:** Type: Search - Description: Retrieves any available data for a target against the IBM XForce database.
* **[*] IntezerSearch:** Type: Search - Description: Retrieves any available data for a target against the Intezer database.
 
----

## Documentation

Use the [Installation Guide](https://github.com/slaughterjames/static/blob/main/docs/install.md) to get started. - ToDo

Go to the [User's Guide](https://github.com/slaughterjames/static/blob/main/docs/user_guide.md) for additional information. -ToDo
