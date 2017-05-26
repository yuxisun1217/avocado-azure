#!/usr/bin/env python

import re
import os
import imp
import base64
import logging
import pprint
import string
import datetime
import subprocess
import yaml
import xml.etree.ElementTree as ET
from optparse import OptionParser

from pylarion.document import Document
from pylarion.work_item import _WorkItem
from pylarion.work_item import TestCase
from pylarion.work_item import UnitTestCase
from pylarion.work_item import BusinessCase
from pylarion.project import Project
from pylarion.project_group import ProjectGroup
from pylarion.test_run import TestRun
from pylarion.test_record import TestRecord

import sys
import ssl
ssl._create_default_https_context = ssl._create_unverified_context

CASE_TYPE = 'testcase'

# Specified which document the case belongs to
case_doc = {
        "01_image_prepare.py":"WALA test plan - image preparation",
        "02_func.py":"WALA test plan - WALA functions",
        "03_general.py":"WALA test plan - general verification",
        "04_life_cycle.py":"WALA test plan - life cycle",
        "05_network.py":"WALA test plan - network",
        "06_settings.py":"WALA test plan - VM settings",
        "07_storage.py":"WALA test plan - storage",
        "08_subscription.py":"WALA test plan - subscription",
        "09_wala_conf.py":"WALA Configuration Verification"
        }

# These cases will not be added into the case list
ignore_case_list = [
        "ImgPrepTest.test_00_preparation",
        "ImgPrepTest.test_01_prepare_image",
        "ImgPrepTest.test_02_convert_image",
        "ImgPrepTest.test_03_import_image_to_azure"
        ]

#CUR_PATH = os.getcwd()
CUR_PATH = os.path.dirname(os.path.realpath(__file__))

# Parse polarion_config.yaml
CONFIG_FILE = '%s/../cfg/polarion_config.yaml' % CUR_PATH
if not os.path.exists(CONFIG_FILE):
    logging.error("No config file: %s" % CONFIG_FILE)
    sys.exit(1)
with open(CONFIG_FILE) as f:
    conf = yaml.load(f.read())

# Set project id
if int(conf["PROJECT"]) == 6:
    PROJ_ID = 'RHEL6'
elif int(conf["PROJECT"]) == 7:
    PROJ_ID = 'RedHatEnterpriseLinux7'
else:
    logging.error("Wrong project. Project: %s" % conf["PROJECT"])
    sys.exit(1)

# Set testrun prefix
if conf["TYPE"] and conf["TYPE"].lower() != "none":
    runtype = ' ' + conf["TYPE"]
else:
    runtype = ''
if conf["TAG"] and conf["TAG"].lower() != "none":
    tag = '-' + conf["TAG"]
else:
    tag = ''
TESTRUN_PREFIX = "WALinuxAgent-{wala_version}{tag} {rhel_version}{runtype}".format(
    wala_version=conf["WALA_VERSION"].replace('.', '_'),
    tag=tag,
    runtype=runtype,
    rhel_version=conf["RHEL_VERSION"].replace('.','_'))

# Set results.xml path
RESULT_PATH = conf["RESULT_PATH"]
JUNIT_XML = '{result_path}/{azure_mode}/results.xml'

# Set log format and path
LOGFILE = "/tmp/pylarion.log"
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [line:%(lineno)3d] %(levelname)s:  %(message)s',
    datefmt='%d %b %Y %H:%M:%S',
    filename=LOGFILE,
    filemode='w'
)

# Other constant parameters. 
ATTACH_TITLE = "log"
SPACE = 'VirtAzureQE'
CASE_PREFIX = "WALA-TC: "
TEMPLATE_ID = 'Build Acceptance type'


def mk_logPath():
    isExists = os.path.exists(LOG_PATH)
    if not isExists:
        os.makedirs(LOG_PATH)


def get_testRecords(xml_file):
    # Prepare the test cases and records from the xml file
    # Return the test cases and records list
    with open(CUR_PATH+"/../cfg/case_map.yaml") as f:
        case_map = yaml.load(f.read())
    logging.info('======Begin to prepare the test cases and records from the xml file======')
    workItems = []
    testRecords = []
    root = ET.parse(xml_file)
    testcase_nodes = root.getiterator("testcase")
    for node in testcase_nodes:
        long_workItem = node.attrib['name']
        workItem = long_workItem.split(':')[-1]
        # Get real case name
        if workItem in ignore_case_list:
            continue
#        workItem = CASE_PREFIX + workItem
        if case_map.has_key(workItem):
            workItem = case_map[workItem]
        # Parse test record from xml file
        testRecord = {}
        testRecord["test_case_id"] = workItem
        testRecord["comment"] = long_workItem
        testRecord["duration"] = node.attrib['time'].split('.')[0]
        testRecord["result"] = "passed"
        node_children = node.getchildren()
        if node_children:
            tag = node_children[0].tag
            if tag == 'skipped':
                continue
            elif tag == 'failure' or tag == 'error':
                testRecord["result"] = "failed"
                auto_casename = testRecord["comment"]
                fail_message = node.getchildren()[0].attrib["message"]
                testRecord["comment"] = "Test Case: " + auto_casename
                testRecord["comment"] += "  Fail message: " + fail_message
                testRecord["log"] = node_children[0].text.strip()
            else:
                logging.info("Result illegal. Case: {casename} Result: {result}".format(casename=workItem, result=tag))
                continue
        workItems.append(workItem)
        testRecords.append(testRecord)
        logging.debug('Get the test record %s from the xml file', testRecord)

    logging.info('======Finish to prepare the test cases and records from the xml file======')

    return workItems, testRecords


#def add_workItems(proj_id, workItems, document, case_type):
#    # Add workItems into the document
#    logging.info('======Begin to add the new test cases to "%s"======', document.title)
#    added_workItems = {}
#    if len(workItems) == 0:
#        logging.info('No new test cases to be added to %s', document.title)
#
#    for workItem in workItems:
#        wi = _WorkItem.create(
#            proj_id,
#            'testcase',
#            workItem,
#            workItem,
#            'open',
#        )
#        tc = TestCase(project_id=proj_id,
#                      work_item_id=wi.work_item_id)
#        # tc.testtype = case_type
#        """
#        tc.testtype = "functional"
#        tc.subtype1 = "-"
#        tc.caselevel = "component"
#        tc.caseimportance = "critical"
#        tc.caseautomation = "automated"
#        tc.update()
#
#        tc = TestCase.create(proj_id,
#                             workItem,
#                             workItem,
#                             caseimportance = "critical",
#                             caselevel = "component",
#                             caseautomation = "automated",
#                             caseposneg = "positive",
#                             testtype = case_type,
#                             subtype1 = "-")
#        tc = TestCase()
#        tc.title = workItem
#        tc.description = workItem
#        tc.status = "draft"
#        tc.caseimportance = "critical"
#        tc.caseautomation = "automated"
#        tc.caseposneg = "positive"
#        tc.testtype = case_type
#        tc.caselevel = "component"
##        tc.casecomponent = "accountsservice"
#        tc.subtype1 = "-"
#        wi = document.create_work_item(None, tc)
#        if wi:
#            logging.info('Createed the test case "%s" in "%s"', wi.title, document.title)
#            added_workItems[wi.title] = wi.work_item_id
#        else:
#            logging.info('Failed to createed the test "%s" in "%s"', wi.title, document.title)
#        """
#        document.move_work_item_here(tc.work_item_id, None)
#        if tc:
#            logging.info('Created the test case "%s" in "%s"', tc.title, document.title)
#            added_workItems[tc.title] = tc.work_item_id
#        else:
#            logging.info('Failed to created the test "%s" in "%s"', tc.title, document.title)
#
#    logging.info('======Finish to add the new test cases to "%s"======', document.title)
#
#    return added_workItems


def get_exits_workItems(proj_id, gs_doc, case_type):
    logging.info('======Begin to get "%s" test cases from "%s"======', case_type, gs_doc)
    # wi_query = 'project.id:%s AND title:VTGS-TC AND document.title:"%s" AND type:%s' \
    #             % (PROJ_ID, GS_DOC, CASE_TYPE)
    wi_query = 'project.id:%s AND document.title:"%s" AND type:%s' % (proj_id, gs_doc, case_type)
    wi_fields = ['work_item_id', 'title', 'type', 'description']
    workItems = _WorkItem.query(wi_query, fields=wi_fields)

    exist_tests = {}
    if workItems:
        logging.info('Found %s work items', len(workItems))
        for workItem in workItems:
            logging.debug('%-12s %-20s %s', workItem.work_item_id, workItem.type, workItem.title)
            exist_tests[workItem.title] = workItem.work_item_id

    logging.info('======Finish to get "%s" test cases from "%s"======', case_type, gs_doc)
    return exist_tests


def create_testRun(proj_id, test_run_id, template_id):
    # Create a test run 
    logging.info('======Create test run %s======', test_run_id)
    tr = TestRun.create(proj_id, test_run_id, template_id)
    logging.info('======Test Run %s is created======', test_run_id)


def submit_testResult(proj_id, test_run_id, template_id, testRecords, all_workItems):
    # Submit the test records from the autotest result
    logging.info('======Begin to add the test records from the autotest to the test run======')
    logging.info('======Total test records number: %s======', len(testRecords))
    try:
        tr = TestRun.search(query=test_run_id, project_id=proj_id)[0]
    except:
        logging.error("No such test run: %s. Exit." % test_run_id)
        sys.exit(1)
    count = 0
    tr.session.default_project = proj_id
    tr.session.tx_begin()
    for testRecord in testRecords:
        logging.info(testRecord)
        rec = TestRecord(project_id = proj_id)
        logging.info('Current Record ID: %s', all_workItems[testRecord["test_case_id"]])
        count += 1
        logging.info('Current Progress: %d/%d', count, len(testRecords))
        rec.test_case_id = all_workItems[testRecord["test_case_id"]]
        rec.comment = testRecord["comment"]
        rec.duration = testRecord["duration"]
        rec.result = testRecord["result"]
        rec.executed_by = tr.logged_in_user_id
        rec.executed = datetime.datetime.now()
        # tr.add_test_record_by_object(rec)
        tr.session.test_management_client.service.addTestRecordToTestRun(tr.uri, rec._suds_object)
        if testRecord.has_key('log'):
            log_file = testRecord["test_case_id"] + "_" + str(count) + ".log"
            log_data = base64.b64encode(testRecord["log"])
            tr.session.test_management_client.service. \
                addAttachmentToTestRecord(tr.uri, count-1, log_file, ATTACH_TITLE, log_data)
            #log_file = LOG_PATH + "/" + testRecord["test_case_id"] + "_" + str(count) + ".log"
            #with open(log_file, 'w') as fp:
            #    fp.writelines(testRecord["log"])
            #fp.close()
            #tr.add_attachment_to_test_record(rec.test_case_id, log_file, ATTACH_TITLE)
        if count % 200 == 0:
            tr.session.tx_commit()
            tr.session.tx_begin()
    tr.session.tx_commit()
    tr.status = "finished"
    tr.update()
    logging.info('======Finish to add the test records from the autotest to the test run======')
    return


def update_polarion(azure_mode, exist_workItems):
    logging.info('project id: %s' % PROJ_ID)
    logging.info('space: %s' % SPACE)
    logging.info('testrun prefix: %s' % TESTRUN_PREFIX)
    logging.info('Azure mode: %s' % azure_mode)
    logging.info('Test the connection')
    proj = Project(PROJ_ID)
    logging.info('The current project name is %s, ID is %s', proj.name, proj.project_id)

#    #Check the document
#    logging.info('======Searching for "%s" document ...======', GS_DOC)
#    doc_query = 'project.id:%s AND id:"%s"' % (PROJ_ID, GS_DOC)
#    doc_fields = ['document_id', 'title', 'project_id', 'home_page_content']
#    docs_autotest = Document.query(doc_query, fields=doc_fields)
#
#    if docs_autotest:
#        doc_autotest = docs_autotest[0]
#        for doc in docs_autotest:
#            logging.info('Found the "%s" document ...', GS_DOC)
#            print "'%s' '%s' '%s'" % (doc.document_id, doc.title, doc.project_id)
#    else:
#        logging.info('NOT found the "%s" document ...', GS_DOC)
#        logging.info('Creating the "%s" document ...', GS_DOC)
#        doc_autotest = Document.create(
#            project_id = PROJ_ID,
#            space = SPACE,
#            document_name = GS_DOC,
#            document_title = GS_DOC,
#            allowed_wi_types = 'requirement',
#            document_type = 'testspecification'
#            )

    # Get the workItems exist in the document
#    exist_workItems = {}
#    for doc in case_doc:
#        exist_workItems = dict(exist_workItems, **get_exits_workItems(PROJ_ID, case_doc[doc], CASE_TYPE))

    # Add the new items to the document
    # First get the test cases not in the document
    xml_workItems, xml_testRecords = get_testRecords(JUNIT_XML.format(result_path=RESULT_PATH, azure_mode=azure_mode))
#    logging.info("===========================================XML WORKITEMS===============================================")
#    logging.info(xml_workItems)
    new_workItems = list(set(xml_workItems)-set(exist_workItems.keys()))
    if new_workItems:
        logging.error("Some automation cases do not exist: %s" % new_workItems)
        sys.exit(1)

    # Not all the workItems in the document are tested in this run
    run_workItems = {}
    for xml_workItem in xml_workItems:
        run_workItems[xml_workItem]=exist_workItems[xml_workItem]

    # Create the log dir to restore the attachments
    #mk_logPath()

    # Create a test run and add the test record from the xml file
    test_run_id = "{testrun_prefix} {azure_mode} Automation {timestr}".format(
            testrun_prefix=TESTRUN_PREFIX, 
            azure_mode=azure_mode,
            timestr=datetime.datetime.now().strftime("%Y-%m-%d %H-%M-%S"))
    create_testRun(PROJ_ID, test_run_id, TEMPLATE_ID)
    submit_testResult(PROJ_ID, test_run_id, TEMPLATE_ID, xml_testRecords, run_workItems)
    return


if __name__ == '__main__':
    # Get the workItems exist in the document
    exist_workItems = {}
    for doc in case_doc:
        exist_workItems = dict(exist_workItems, **get_exits_workItems(PROJ_ID, case_doc[doc], CASE_TYPE))
    # Support both ASM and ARM results
    if os.path.isdir(RESULT_PATH+"/ASM"):
        update_polarion("ASM", exist_workItems)
    if os.path.isdir(RESULT_PATH+"/ARM"):
        update_polarion("ARM", exist_workItems)
