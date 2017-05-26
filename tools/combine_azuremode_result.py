import sys
import os
import logging
import sqlite3
from datetime import datetime
from optparse import OptionParser

from xml.etree.ElementTree import ElementTree
from xml.etree.ElementTree import Element
from xml.etree.ElementTree import SubElement
from xml.etree.ElementTree import tostring

class Skip(Exception):
    pass

class AddAzuremode(object):
    def __init__(self, result_file, azure_mode):
        self.azure_mode = azure_mode
        self.testsuite_node = self._get_node(self._get_root(result_file), "testsuite")
        self.testsuite_attrib_dict = {"errors":self._get_testsuite_value("errors"),
                                      "failures":self._get_testsuite_value("failures"),
                                      "skipped":self._get_testsuite_value("skipped"),
                                      "tests":self._get_testsuite_value("tests"),
                                      "time":self._get_testsuite_value("time")}
                                      

    def _get_root(self, result_file):
        if not os.path.exists(result_file):
            logging.error("No result file: {0}. ".format(result_file))
            raise Skip
        else:
            try:
                tree = ElementTree(file=result_file)
            except Exception as e:
                logging.error("Fail to parse result file {0}. Exit. Exception: {1}".format(result_file, e))
                sys.exit(1)
            return tree.getroot()

    def _get_node(self, parent_node, keystring):
        if parent_node.tag == keystring:
            node = parent_node
        elif parent_node.find("./"+keystring):
            node = parent_node.find("./"+keystring)
        else:
            logging.error("{0} node is not found. Exit.".format(keystring))
            raise Skip
        return node

    def _get_testsuite_value(self, attrib):
        if attrib in self.testsuite_node.attrib:
            return int(float(self.testsuite_node.attrib[attrib]))
        else:
            return 0

    def insert_azuremode_attrib(self):
        for testcase_node in self.testsuite_node.findall("./testcase"):
            if "azuremode" not in testcase_node.attrib:
                testcase_node.set("azuremode", self.azure_mode)
        return self.testsuite_node


if __name__ == "__main__":
    usage = "usage: %prog -p <project> -t <team> -r <testrun_prefix> [-d <database> -f <autotest_xml> -o <output_xml>] [-v]"
    parser = OptionParser(usage)
    parser.add_option('-p', '--path', dest='resultpath', default='.', action='store',
                      help='The path to the result folder.', metavar='RESULT_PATH')
    parser.add_option('-o', '--output', dest='outputfile', default='merged_results.xml', action='store',
                      help='The output file. Default is merged_results.xml', metavar='OUTPUTFILE')
    parser.add_option('-v', '--verbose', dest='verbose', default=False, action='store_true',
                      help='Enable debug log')

    options, args = parser.parse_args()
    RESULTPATH = options.resultpath.rstrip('/')
#    TEAM = options.team
#    DATABASE = options.database
#    TESTRUN_PREFIX = options.testrunprefix
#    AUTOTESTXML = options.autotestxml
    OUTPUTFILE = options.outputfile
    DEBUG = options.verbose

#    if not PROJECT or not TEAM or not TESTRUN_PREFIX:
#        parser.print_help()
#        parser.error("Must specific project, team and testrun prefix!")

    # Define log level
    if DEBUG:
        LOGLEVEL = logging.DEBUG
    else:
        LOGLEVEL = logging.INFO

    logging.basicConfig(
            level=LOGLEVEL,
            format='%(asctime)s %(levelname).4s %(message)s',
            datefmt='[%Y-%m-%d %H:%M:%S]'
            )


    def _sum_dict(*objs):  
            _keys = set(sum([obj.keys() for obj in objs],[]))  
            _total = {}  
            for _key in _keys:  
                _total[_key] = sum([obj.get(_key,0) for obj in objs])  
            return _total 


    def _indent(elem, level=0):
        """
        Return a pretty-printed XML string for the Element.
        """
        i = "\n" + level*"  "
        if len(elem):
            if not elem.text or not elem.text.strip():
                elem.text = i + "  "
            if not elem.tail or not elem.tail.strip():
                elem.tail = i
            for elem in elem:
                _indent(elem, level+1)
            if not elem.tail or not elem.tail.strip():
                elem.tail = i
        else:
            if level and (not elem.tail or not elem.tail.strip()):
                elem.tail = i


# Main process
    root = Element("testsuites")
    tree = ElementTree(root)
    testsuite_node = SubElement(root, "testsuite", {"name":"avocado"})
    total_testsuite_dict = {}
    for azuremode in ["ASM","ARM"]:
        try:
            am = AddAzuremode(RESULTPATH+"/"+azuremode+"/results.xml", azuremode)
            am_node = am.insert_azuremode_attrib()
            am_testsuite_dict = am.testsuite_attrib_dict
            logging.info(azuremode+" testsuite_dict:")
            logging.info(am_testsuite_dict)
        except Skip:
            continue
        except Exception as e:
            logging.error("Fail to parse result file of {0} mode. Exception: {1}".format(azuremode, e))
            sys.exit(1)
        total_testsuite_dict = _sum_dict(total_testsuite_dict, am_testsuite_dict)
        for testcase_node in am_node.findall("testcase"):
            testsuite_node.append(testcase_node)
        logging.info("{0} result is merged.".format(azuremode))
    # Set errors/failures/skipped/tests/time of testsuite
    logging.info("total_testsuite_dict:")
    logging.info(total_testsuite_dict)
    for attrib in total_testsuite_dict:
        testsuite_node.set(attrib, str(total_testsuite_dict[attrib]))
    _indent(root)
    tree.write(OUTPUTFILE)
    logging.info("Result is merged into {0}.".format(OUTPUTFILE))
    

