import os
import sys
import commands
from optparse import OptionParser

REALPATH = os.path.split(os.path.realpath(__file__))[0]
CONFIGFILE = REALPATH + "/config.yaml"
PW_ENCRYPT_FILE = REALPATH + "/password/password_encrypt"
PW_FILE = REALPATH + "/password.yaml"

ConfigYaml="""\
type: %(type)s
project: %(project)s
wala_version: %(wala_version)s
upstream: %(upstream)s
tag: %(tag)s
case_group: %(case_group)s
submit_result: True
base_url: "http://download.eng.pek2.redhat.com/rel-eng/"
store_dir: "/home/autotest/"
%(passwords)s
"""


if __name__ == "__main__":
    usage = "usage: %prog [-t type -r rhel_version -p project -P password]"
    parser = OptionParser(usage)
    parser.add_option('-t', '--type', dest='type', action='store', default='onpremise',
                      help='The type of the test. Default value is onpremise. '
                           '(onpremise/ondemand/customize)', metavar='TYPE')
    parser.add_option('-r', '--rhel_version', dest='rhel_version', action='store', default=None,
                      help='The RHEL version. Only be used in onpremise type.'
                           '(e.g. --rhel_version=RHEL-6.9-20161110.2)',
                      metavar='RHEL_VERSION')
    parser.add_option('-p', '--project', dest='project', action='store',
                      help='The RHEL project. (e.g. --project=7.3)', metavar='PROJECT')
    parser.add_option('-w', '--wala_version', dest='wala_version', action='store', default=None,
                      help='The WALA version. (e.g. --wala_version=2.2.0)', metavar='WALA_VERSION')
    parser.add_option('-c', '--case_group', dest='case_group', action='store', default='function',
                      help='The test case group. (e.g. --case_group=function)', metavar='CASE_GROUP')
    parser.add_option('-T', '--tag', dest='tag', action='store', default=None,
                      help='The tag of the test run. (e.g. --tag=scratch)', metavar='TAG')
    parser.add_option('-u', '--upstream', dest='upstream', action='store', default=True,
                      help='The source of the WALA package. (e.g. --upstream=True)', metavar='UPSTREAM')
    parser.add_option('-P', '--password', dest='password', action='store',
                      help='The password to decrypt the password_encrypt', metavar="PASSWORD")

    options, args = parser.parse_args()

    if not options.type:
        parser.print_help()
        parser.error("Must specify type!")
    if not options.password:
        parser.print_help()
        parser.error("Must specify password!")
    if not options.project:
        parser.print_help()
        parser.error("Must specify project!")

    # Decrypt passwords
    if not os.path.isfile(PW_ENCRYPT_FILE):
        print "No such file: {0}".format(PW_ENCRYPT_FILE)
        sys.exit(1)
    commands.getstatusoutput("openssl enc -des3 -d -in {0} -out {1} -k {2}"
                             .format(PW_ENCRYPT_FILE, PW_FILE, options.password))
    with open(PW_FILE, 'r') as f:
        passwords = f.read()

    # Make config string
    if options.type == "onpremise":
        type = "onpremise\nonpremise:\n    rhel_version: {0}".format(options.rhel_version)
    else:
        type = options.type
    config_yaml_dict = {
        "type": type,
        "project": options.project,
        "wala_version": options.wala_version,
        "upstream": options.upstream,
        "tag": options.tag,
        "case_group": options.case_group,
        "passwords": passwords
    }

    # Write config string into config.yaml
    with open(CONFIGFILE, 'w') as f:
        f.write(ConfigYaml % config_yaml_dict)
