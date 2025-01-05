#python imports
#standard widely used classes, add  or remove as needed
import sys
import os
import subprocess
from termcolor import colored
#third-party imports

#programmer generated imports
#This is my log generator, you could easily replace with your own
from logger import logger

'''
***BEGIN DESCRIPTION***
Type: LNK - Description: Attempts to detect files embedded in Microsoft Windows Shortcut files.
***END DESCRIPTION***
'''
def POE(POE):
    if (POE.logging == True): 
        LOG = logger() 

    newlogentry = ''
    output = POE.logdir + 'lnkdetect.txt'
    #Sigs:
    pdf_signature = b'%PDF-'  # PDF file signature
    pdf_eof_marker = b'%%EOF'  # PDF end marker
    zip_signature = b'PK\x03\x04'  # ZIP file signature
    rar_signature = b'Rar!\x1a\x07\x00'  # RAR file signature
    exe_signature = b'MZ'  # EXE file signature
    hwp_signature = b'HWP Document File'  # HWP file signature
    doc_signature = b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1'  # DOC signature
    docx_signature = b'\x50\x4B\x03\x04'  # DOCX (PKZIP) signature    
    buffer_size = 8192  # Read in chunks

    if (POE.logging == True):
        newlogentry = 'Module: lnkdetect'           
        LOG.WriteStrongLog(POE.logdir, POE.targetfilename, newlogentry)

    if (POE.debug == True):
        print ('[DEBUG] POE.extension: ' + POE.extension)

    if ((POE.extension.find('lnk') == -1) and (POE.extension.find('LNK') == -1)):
        print (colored('\r\n[x] Unable to execute lnkdetect - file must be Microsoft Windows Shortcut.', 'red', attrs=['bold']))
        newlogentry = 'Unable to execute lnkdetect - file must be Microsoft Windows Shortcut.'
        LOG.WriteStrongSubLog(POE.logdir, POE.targetfilename, newlogentry)
        return -1    

    print (colored('\r\n[*] Running lnkdetect against: ' + POE.target, 'white', attrs=['bold']))

    try:
        with open(POE.target, 'rb') as file:
            while chunk := file.read(buffer_size):
                # Look for the PDF signature in the chunk
                pdf_start = chunk.find(pdf_signature)
                zip_start = chunk.find(zip_signature)
                rar_start = chunk.find(rar_signature)
                exe_start = chunk.find(exe_signature)
                hwp_start = chunk.find(hwp_signature)
                doc_start = chunk.find(doc_signature)
                docx_start = chunk.find(docx_signature)
                if pdf_start != -1:
                    #print(f"PDF found at position {pdf_start}")
                    print (f'[-] Embedded PDF found at position {pdf_start}')

                    if ((POE.logging == True) and (POE.nolinksummary == False)):
                        newlogentry = f'[-] Embedded PDF found at position {pdf_start}'
                        LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
        
                    # Found the start of the PDF
                    file.seek(-len(chunk) + pdf_start, os.SEEK_CUR)
                    # Extract the remaining content as the PDF
                    pdf_data = file.read()  # Read the rest of the file

                    # Look for the EOF marker in the PDF data
                    eof_pos = pdf_data.rfind(pdf_eof_marker)
                    if eof_pos != -1:
                        pdf_data = pdf_data[:eof_pos + len(pdf_eof_marker)]  # Trim data after EOF

                    with open(POE.logdir + 'output_pdf', 'wb') as pdf_file:
                        pdf_file.write(pdf_data)

                    #print(f"PDF extracted to: {POE.logdir + 'output_pdf'}")
                    print (colored('[*] lnkdetect PDF data has been generated to file here: ', 'green') + colored(POE.logdir + 'output_pdf', 'blue', attrs=['bold']))

                    if ((POE.logging == True) and (POE.nolinksummary == False)):
                        newlogentry = 'lnkdetect PDF data has been generated to file here: <a href=\"' + POE.logdir + 'output_pdf' + '\"> lnkdetect PDF Output </a>'
                        LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)                     
                    #return True
                elif zip_start != -1:
                    print (f'[-] Embedded ZIP found at position {zip_start}')
                    if ((POE.logging == True) and (POE.nolinksummary == False)):
                        newlogentry = f'[-] Embedded ZIP found at position {zip_start}'
                        LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)                    

                    #print(f"ZIP extracted to: {POE.logdir + 'output_zip'}")
                    #return True
                elif rar_start != -1:
                    print (f'[-] Embedded RAR found at position {rar_start}')
                    if ((POE.logging == True) and (POE.nolinksummary == False)):
                        newlogentry = f'[-] Embedded RAR found at position {rar_start}'
                        LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)

                    #print(f"RAR extracted to: {POE.logdir + 'output_rar'}")
                    #return True
                elif exe_start != -1:
                    print (f'[-] Embedded EXE found at position {exe_start}')
                    if ((POE.logging == True) and (POE.nolinksummary == False)):
                        newlogentry = f'[-] Embedded EXE found at position {exe_start}'
                        LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)

                    #print(f"EXE extracted to: {POE.logdir + 'output_exe'}")
                    #return True
                elif hwp_start != -1:
                    print (f'[-] Embedded HWP found at position {hwp_start}')
                    if ((POE.logging == True) and (POE.nolinksummary == False)):
                        newlogentry = f'[-] Embedded HWP found at position {hwp_start}'
                        LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)

                    #print(f"HWP extracted to: {POE.logdir + 'output_hwp'}")
                    #return True
                elif doc_start != -1:
                    print (f'[-] Embedded DOC found at position {doc_start}')
                    if ((POE.logging == True) and (POE.nolinksummary == False)):
                        newlogentry = f'[-] Embedded DOC found at position {doc_start}'
                        LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)

                    #print(f"DOC extracted to: {POE.logdir + 'output_doc'}")
                    #return True 
                elif docx_start != -1:
                    print (f'[-] Embedded DOCX found at position {docx_start}')
                    if ((POE.logging == True) and (POE.nolinksummary == False)):
                        newlogentry = f'[-] Embedded DOCX found at position {docx_start}'
                        LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)

                    #print(f"DOCX extracted to: {POE.logdir + 'output_docx'}")
                    #return True

        if (pdf_start == -1):
            print (colored("[-] No embedded PDF found in the LNK file.", 'yellow', attrs=['bold']))
            if ((POE.logging == True) and (POE.nolinksummary == False)):
                newlogentry = '[-] No embedded PDF found in the LNK file.'
                LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
        if (zip_start == -1):
            print (colored("[-] No embedded ZIP found in the LNK file.", 'yellow', attrs=['bold']))
            if ((POE.logging == True) and (POE.nolinksummary == False)):
                newlogentry = '[-] No embedded ZIP found in the LNK file.'
                LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
        if (rar_start == -1):
            print (colored("[-] No embedded RAR found in the LNK file.", 'yellow', attrs=['bold']))
            if ((POE.logging == True) and (POE.nolinksummary == False)):
                newlogentry = '[-] No embedded RAR found in the LNK file.'
                LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry) 
        if (exe_start == -1):
            print (colored("[-] No embedded EXE found in the LNK file.", 'yellow', attrs=['bold']))
            if ((POE.logging == True) and (POE.nolinksummary == False)):
                newlogentry = '[-] No embedded EXE found in the LNK file.'
                LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry) 
        if (hwp_start == -1):
            print (colored("[-] No embedded HWP found in the LNK file.", 'yellow', attrs=['bold']))
            if ((POE.logging == True) and (POE.nolinksummary == False)):
                newlogentry = '[-] No embedded HWP found in the LNK file.'
                LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry) 
        if (doc_start == -1):
            print (colored("[-] No embedded DOC found in the LNK file.", 'yellow', attrs=['bold']))
            if ((POE.logging == True) and (POE.nolinksummary == False)):
                newlogentry = '[-] No embedded DOC found in the LNK file.'
                LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
        if (docx_start == -1):
            print (colored("[-] No embedded DOCX found in the LNK file.", 'yellow', attrs=['bold']))
            if ((POE.logging == True) and (POE.nolinksummary == False)):
                newlogentry = '[-] No embedded DOCX found in the LNK file.'
                LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)                                                                                          

        #return False
    except Exception as e:
        print (colored(f'[x] Error processing the LNK file: {e}', 'red', attrs=['bold']))
        return -1
    
    #print (colored('[*] lnkdetect data has been generated to file here: ', 'green') + colored(output, 'blue', attrs=['bold']))

    #if ((POE.logging == True) and (POE.nolinksummary == False)):
    #    newlogentry = 'lnkdetect data has been generated to file here: <a href=\"' + output + '\"> lnkdetect Output </a>'
    #    LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)    

    return 0
