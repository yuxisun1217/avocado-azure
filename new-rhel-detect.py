##############################################
# This script is used to detect new RHEL build
# and run avocado-azure automatically.
##############################################

import os
import re
import commands
import time
import smtplib
from email.mime.text import MIMEText
from email.header import Header

PYTHON = "/usr/bin/python"
AVOCADO_AZURE = os.path.split(os.path.realpath(__file__))[0]
SCRIPT = "%s/tools/azure_image_prepare/azure_image_prepare.py" % AVOCADO_AZURE
LOG = "/tmp/new-rhel-detach.log"
PREFIX = time.strftime("[%Y-%m-%d %H:%M:%S]", time.localtime())

def log(msg):
    with open(LOG,'a') as f:
        f.write("%s %s\n" % (PREFIX, msg))

def run(cmd):
    status, output = commands.getstatusoutput(cmd)
    return output

def sendmail(build):
    sender = 'xintest@redhat.com'
    receivers = ['yuxisun@redhat.com']  
    message = MIMEText('There\'s a new RHEL build %s. Run avocado-azure.' % build, 'plain')
    message['From'] = Header(sender)
    message['To'] =  Header(';'.join(receivers))
    message['Subject'] = Header('New Build Notification')
    try:
        smtpObj = smtplib.SMTP('localhost')
        smtpObj.sendmail(sender, receivers, message.as_string())
        log("Send mail successfully.")
    except smtplib.SMTPException:
        log("Cannot send mail.")

def main():
    latest_build=run("%s %s -rhelbuild" % (PYTHON, SCRIPT))
    local_build=run("%s %s -localbuild" % (PYTHON, SCRIPT))
    if latest_build == local_build:
        log("No new build")
    else:
        log("Have new build: %s" % latest_build)
        os.chdir(AVOCADO_AZURE)
        run("%s run.py" % PYTHON)
        sendmail(latest_build)

if __name__ == "__main__":
    main()
