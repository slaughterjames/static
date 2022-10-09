#python imports
import sys
import os
import json
import time
import extract_msg
import email
from email import policy
from email.header import decode_header, make_header
from email.parser import BytesParser
from termcolor import colored

#third-party imports
#No third-party imports

#programmer generated imports
from logger import logger
from fileio import fileio

'''
***BEGIN DESCRIPTION***
Type: Email - Description: Reads an eml or msg file and outputs the contents.
***END DESCRIPTION***
'''
def POE(POE):

    if (POE.logging == True): 
        LOG = logger() 
    newlogentry = ''
    reademail_dump = ''
    reademail_output_data = ''
    output = POE.logdir + 'Reademail.txt'

    FI = fileio()

    if (POE.logging == True):
        newlogentry = 'Module: reademail'           
        LOG.WriteStrongLog(POE.logdir, POE.targetfilename, newlogentry)

    print (colored('\r\n[*] Running reademail against: ' + POE.target, 'white', attrs=['bold']))

    if (POE.extension == 'eml'):
        print (colored('[*] Target is .eml...', 'green', attrs=['bold']))
        texts = []
        text = ''
        count = 0
        failedcount = 0

        with open(POE.target, 'rb') as filedata:
            name = filedata.name  # Get file name
            msg = BytesParser(policy=policy.default).parse(filedata)
        text += 'Date: ' + msg['date'] + '\n'
        text += 'To: ' + msg['to'] + '\n'
        text += 'From: ' + msg['from'] + '\n'
        text += 'Subject: ' + msg['subject'] + '\n\r'
        #text += str(msg.get_body(preferencelist=('plain'))#.get_content()
        filedata.close()

        print (colored('[-] Message Date: ' + msg['date'],'white'))
        print (colored('[-] Message To: ' + msg['to'],'white'))
        print (colored('[-] Message From: ' + msg['from'],'white'))
        print (colored('[-] Message Subject: ' + msg['subject'],'white'))
        if (POE.logging == True):
            newlogentry = 'Message Date: ' + msg['date']
            LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
            newlogentry = 'Message To: ' + msg['to']
            LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
            newlogentry = 'Message From: ' + msg['from']
            LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
            newlogentry = 'Message Subject: ' + msg['subject']
            LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)

        if (POE.debug == True):
            print ('[DEBUG] name: ' + name)
            print ('[DEBUG] text: ' + str(text))
 
        print (colored('[*] Reademail e-mail body data has been generated to file here: ', 'green') + colored(output, 'blue', attrs=['bold']))
        FI.WriteLogFile(output, text) 

        message = email.message_from_file(open(POE.target))
        suffix=None
        filenames = []
        content_type = ''

        if message.get_content_maintype() == 'multipart':
            for part in message.walk():
                if (POE.debug == True):
                    print ('[DEBUG] Content Type: ' + part.get_content_maintype())
                if part.get_content_maintype() == 'multipart': continue                
                if ((part.get('Content-Type').find('application/octet-stream') != -1) or (part.get('Content-Type').find('application/x-zip-compressed') != -1) or (part.get('Content-Type').find('application') != -1) or (part.get('Content-Type').find('image') != -1) or (part.get('Content-Type').find('text/html') != -1) or (part.get('Content-Type').find('application/rtf') != -1)):
                    filename = part.get_filename()
                    try:
                        if suffix:
                            filename = ''.join( [filename.split('.')[0], '_', suffix, '.', filename.split('.')[1]])
                        filepath = os.path.join(POE.logdir, filename)
                        fb = open(filepath,'wb')
                        fb.write(part.get_payload(decode=True))
                        fb.close()
                        filenames.append(filename)
                    except Exception as e:
                        print (colored('[x] Unable to extract attachment! ' + str(e), 'red', attrs=['bold']))
                        if (POE.logging == True):
                            newlogentry = 'Unable to extract attachment! ' + str(e)
                            LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
                        failedcount += 1
                        continue  

            for fnames in filenames:
                count += 1
                if (POE.debug == True): 
                    print ('[DEBUG] fnames: ' + fnames)

                print (colored('[*] Attachment extracted: ' + fnames, 'green'))# + colored(POE.logdir + fnames, 'blue', attrs=['bold']))
                if (POE.logging == True):
                    newlogentry = 'Attachment extracted: ' + fnames + '\n'
                    LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)

            print (colored('[*] ' + str(count) + ' total attachments extracted to: ', 'green') + colored(POE.logdir, 'blue', attrs=['bold']))
            if (POE.logging == True):
                newlogentry = str(count) + ' total attachments extracted to: <a href=\"' + POE.logdir + '\">' + POE.logdir + '</a>'
                LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)

            print (colored('[*] ' + str(failedcount) + ' total attachments failed to be extracted...', 'yellow'))
            if (POE.logging == True):
                newlogentry = str(failedcount) + ' total attachments failed to be extracted...'
                LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
        else:
            print (colored('[-] No attachments found to extract...', 'yellow', attrs=['bold']))
            if (POE.logging == True):
                newlogentry = 'No attachments found to extract...'
            LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)

    elif(POE.extension == 'msg'):
        print (colored('[*] Target is .msg...', 'green', attrs=['bold']))
        email_msg = extract_msg.openMsg(POE.target)
        #attachments = email_msg.attachments
        attachment = email_msg.attachments
        count = 0

        if (POE.debug == True):
            print ('email_msg.sender: ' + email_msg.sender)
            print ('email_msg.to: ' + email_msg.to)
            print ('email_msg.subject: ' + email_msg.subject)
            print ('email_msg.date: ' + email_msg.date)
            print ('email_msg.body: ' + email_msg.body)

        if attachment:
            messageto = str(make_header(decode_header(email_msg.to)))
            messagefrom = str(make_header(decode_header(email_msg.sender)))
            print (colored('[-] Message Date: ' + email_msg.date,'white'))
            print (colored('[-] Message To: ' + messageto,'white'))
            print (colored('[-] Message From: ' + messagefrom,'white'))
            print (colored('[-] Message Subject: ' + email_msg.subject,'white'))
            if (POE.logging == True):
                newlogentry = 'Message Date: ' + email_msg.date
                LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
                newlogentry = 'Message To: ' + messageto
                LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
                newlogentry = 'Message From: ' + messagefrom
                LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
                newlogentry = 'Message Subject: ' + email_msg.subject
                LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)

            for attachment in email_msg.attachments:
                count += 1
                attachment.save(customPath=POE.logdir)
                print (colored('[*] Attachment extracted: ' + attachment.shortFilename, 'green'))
                if (POE.logging == True):
                    newlogentry = 'Attachment extracted: ' + attachment.shortFilename 
                    LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)     
   
            print (colored('[*] ' + str(count) + ' total attachments extracted to: ', 'green') + colored(POE.logdir, 'blue', attrs=['bold']))
            if (POE.logging == True):
                newlogentry = str(count) + ' total attachments extracted to: <a href=\"' + POE.logdir + '\">' + POE.logdir + '</a>'
                LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
        else:
            messageto = str(make_header(decode_header(email_msg.to)))
            messagefrom = str(make_header(decode_header(email_msg.sender)))
            print (colored('[-] Message Date: ' + email_msg.date,'white'))            
            print (colored('[-] Message To: ' + messageto,'white'))
            print (colored('[-] Message From: ' + messagefrom,'white'))
            print (colored('[-] Message Subject: ' + email_msg.subject,'white'))
            if (POE.logging == True):
                newlogentry = 'Message Date: ' + email_msg.date
                LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
                newlogentry = 'Message To: ' + messageto
                LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
                newlogentry = 'Message From: ' + messagefrom
                LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
                newlogentry = 'Message Subject: ' + email_msg.subject
                LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)
            print (colored('[-] No attachments found to extract...', 'yellow', attrs=['bold']))
            if (POE.logging == True):
                newlogentry = 'No attachments found to extract...'
                LOG.WriteSubLog(POE.logdir, POE.targetfilename, newlogentry)

    else:
        print (colored('[x] Target is not a supported e-mail type.  Must be .eml or .msg!', 'red', attrs=['bold']))
        return -1

    return 0
