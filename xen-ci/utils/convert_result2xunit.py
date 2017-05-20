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


class ResultConvert(object):
    def __init__(self, team, project, database, result_xml):
        self.team = team
        self.project = project
        table = "casemap_{0}_{1}".format(team, project)
        self.case_mapping = self._get_casemap(database, table)
        self.result_xml = result_xml

    def _get_casemap(self, database, table):
        """
        Get case map from database. 
        return: polarionID_autocase dict
        """
        if not os.path.isfile(database):
            logging.error("Database {0} doesn't exist. Exit.".format(database))
            sys.exit(1)
        case_mapping = {}
        try:
            with sqlite3.connect(database) as con:
                cur = con.cursor()
                logging.debug("select * from {0}".format(table))
                cur.execute("select * from {0}".format(table))
                for polarion_case_id, auto_case_name in cur.fetchall():
                    case_mapping[auto_case_name] = polarion_case_id
        except sqlite3.OperationalError:
            logging.error("No such table: {0}. Exit.".format(table))
            sys.exit(1)
        if not case_mapping:
            logging.error("No case in the database. Exit.")
            sys.exit(1)
        return case_mapping

    def _indent(self, elem, level=0):
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
                self._indent(elem, level+1)
            if not elem.tail or not elem.tail.strip():
                elem.tail = i
        else:
            if level and (not elem.tail or not elem.tail.strip()):
                elem.tail = i

    def _move_node_uplayer(self, child_node, grandparent_node):
        """
        Move a node from parent node to grandparent node
        """
        if not isinstance(child_node, Element):
            return
        for parent_node in grandparent_node.getchildren():
            if child_node in parent_node.getchildren():
                parent_node.remove(child_node)
                grandparent_node.append(child_node)

    def convert_result(self):
        """
        Insert properties into result xml file.
        """
        if not os.path.isfile(self.result_xml):
            logging.error("No result file {0}. Exit.".format(self.result_xml))
        tree = ElementTree(file=self.result_xml)
        root = tree.getroot()
        if root.tag == "testsuite":
            testsuite_node = root
        elif root.find("./testsuite") is not None:
            testsuite_node = root.find("./testsuite")
        else:
            logging.error("testsuite node is not found. Exit.")
            sys.exit(1)
        newroot = Element("testsuites")
        newtree = ElementTree(newroot)
        # Add testsuites properties(test run id)
        properties_node = SubElement(newroot, "properties")
        SubElement(properties_node, "property", {"name":"polarion-response-myteamsname", "value":TEAM+"qe"})
        SubElement(properties_node, "property", {"name":"polarion-project-id", "value":POLARION_PROJECT})
        SubElement(properties_node, "property", {"name":"polarion-testrun-id", "value":TESTRUN_ID})
        # Append original testsuite node under testsuites properties
        newroot.append(testsuite_node)
        # Remove invalid testcase nodes
        count = 0
        for testcase_node in testsuite_node.findall("./testcase"):
            long_name = testcase_node.attrib["name"]
            if TEAM == "azure":
                autocase_name = testcase_node.attrib["name"].split('.')[-1]
                comment = long_name
                config = testcase_node.attrib.get("azuremode", long_name)
                del testcase_node.attrib["azuremode"]
            elif TEAM == "xen":
                autocase_name = testcase_node.attrib["name"].split('.')[-1]
                comment = long_name
                config = long_name
            elif TEAM == "libguestfs":
                autocase_name = testcase_node.attrib["name"].split('.')[-1]
                comment = long_name
                config = long_name
            else:
                logging.error("Team {0} is unavailable. Exit.".format(team))
                sys.exit(1)
            # If testcase is skipped, ignore this case
            if testcase_node.find("./skipped") is not None:
                logging.warn("Autocase {0} is not run. Skip.".format(autocase_name))
                testsuite_node.remove(testcase_node)
                continue
            # If testcase is not skipped, match autocase_name with database autocase_name, insert polarion id and parameter
            try:
                case_id = self.case_mapping.get(autocase_name)
            except Exception as e:
                logging.warn("Case {0} doesn't exist in case map. Exception: {1}".format(testcase_node.attrib["name"], str(e)))
                testsuite_node.remove(testcase_node)
                continue
            if not case_id:
                logging.warn("Autocase {0} has no polarion id. Skip.".format(autocase_name))
                testsuite_node.remove(testcase_node)
                continue
            # Move the <system-out> out of <failure> or <error> node
            self._move_node_uplayer(testcase_node.find(".//system-out"), testcase_node)
            properties_node = SubElement(testcase_node, "properties")
            property_node = SubElement(properties_node, "property", {"name":"polarion-testcase-id", "value":case_id})
            property_node = SubElement(properties_node, "property", {"name":"polarion-testcase-comment", "value":comment})
            property_node = SubElement(properties_node, "property", {"name":"polarion-parameter-config", "value":config})
            logging.debug("Autocase {0} is converted.".format(autocase_name))
            count += 1
        self._indent(newroot)
        newtree.write(OUTPUTFILE)
        logging.info("{0} cases are converted into {1}.".format(count, OUTPUTFILE))


if __name__ == "__main__":
    usage = "usage: %prog -p <project> -t <team> -r <testrun_prefix> [-d <database> -f <autotest_xml> -o <output_xml>] [-v]"
    parser = OptionParser(usage)
    parser.add_option('-f', '--file', dest='autotestxml', default='result.xml', action='store',
                      help='The autotest result xml file fullname. Default is result.xml', metavar='AUTOTEST_RESULT')
    parser.add_option('-o', '--output', dest='outputfile', default="result2polarion.xml", action='store',
                      help='The file that will be written in', metavar='OUTPUTFILE')
    parser.add_option('-p', '--project', dest='project', action='store',
                      help='The project name(should match the database name). e.g. rhel6/rhel7', metavar='PROJECT')
    parser.add_option('-t', '--team', dest='team', action='store',
                      help='The team name(should match the database name). e.g. xen/libguestfs/azure', metavar='TEAM')
    parser.add_option('-d', '--database', dest='database', default='testcases.db', action='store',
                      help='The database file fullname. Default is testcases.db', metavar='DATABASE')
    parser.add_option('-r', '--testrunprefix', dest='testrunprefix', action='store',
                      help='The prefix to use for the Polarion run name',metavar='TESTRUNPREFIX')
    parser.add_option('-v', '--verbose', dest='verbose', default=False, action='store_true',
                      help='Enable debug log')

    options, args = parser.parse_args()
    PROJECT = options.project
    TEAM = options.team
    DATABASE = options.database
    TESTRUN_PREFIX = options.testrunprefix
    AUTOTESTXML = options.autotestxml
    OUTPUTFILE = options.outputfile
    DEBUG = options.verbose

    if not PROJECT or not TEAM or not TESTRUN_PREFIX:
        parser.print_help()
        parser.error("Must specific project, team and testrun prefix!")

    # Define polarion project name
    project_dict = {'rhel6':'RHEL6',
                    'rhel7':'RedHatEnterpriseLinux7'}
    if PROJECT in project_dict:
        POLARION_PROJECT = project_dict[PROJECT]
    else:
        parser.print_help()
        parser.error("Wrong project! Must be {0}. Exit.".format('/'.join(project_dict)))

    # Define test run id
    timestr = datetime.now().strftime("%Y-%m-%d %H-%M-%S")
    TESTRUN_ID = TESTRUN_PREFIX + " " + timestr

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

    # Main process
    con = ResultConvert(team=TEAM, project=PROJECT, database=DATABASE, result_xml=AUTOTESTXML)
    con.convert_result()
