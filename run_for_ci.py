import pdb
import re
import os
import sys
import time
import shutil
import json
import yaml
import logging
from optparse import OptionParser
from azuretest.utils_misc import *
import ondemand_provision

POSTFIX = time.strftime("%Y%m%d%H%M")
AVOCADO_PATH = os.path.split(os.path.realpath(__file__))[0]
OSDISK_PATH = "{0}/ondemand_osdisk".format(AVOCADO_PATH)
IGNORE_LIST = ["SettingsTest.test_reset_access_successively",
               "SettingsTest.test_reset_pw_after_capture",
               "StorageTest.test_attach_detach_64_disks"]
SUBMIT_RESULT = yaml.load(file('%s/config.yaml' % AVOCADO_PATH))["submit_result"]
LOGFILE = "/tmp/run-avocado-azure/run-avocado-azure.log-" + POSTFIX
if not os.path.isdir(os.path.dirname(LOGFILE)):
    os.makedirs(os.path.dirname(LOGFILE))

logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(filename)s %(levelname)s %(message)s',
                    datefmt='[%Y-%m-%d %H:%M:%S]',
                    filename=LOGFILE,
                    filemode='w')


def config():
    avocado_conf = '/etc/avocado/avocado.conf'
    comp_test = re.compile('^test_dir = .*$')
    comp_data = re.compile('^data_dir = .*$')
    comp_logs = re.compile('^logs_dir = .*$')
    with open(avocado_conf, 'r') as f:
        data = f.readlines()
    new_data = ""
    for line in data:
        if re.findall(comp_test, line):
            line = "test_dir = %s/tests\n" % AVOCADO_PATH
        elif re.findall(comp_data, line):
            line = "data_dir = %s/data\n" % AVOCADO_PATH
        elif re.findall(comp_logs, line):
            line = "logs_dir = %s/job-results\n" % AVOCADO_PATH
        new_data += line
    with open(avocado_conf, 'w') as f:
        f.write(new_data)


class Run(object):
    def __init__(self, azure_mode='asm'):
        self.azure_mode = azure_mode
        self.avocado_path = AVOCADO_PATH
        self.job_path = "%s/job-results/latest" % self.avocado_path
        config_file = "%s/config.yaml" % self.avocado_path
        with open(config_file, 'r') as f:
            data=yaml.load(f)
        store_dir = data.get("store_dir", "/home/autotest").rstrip('/')
        self.result_path = "%s/run-results/%s" % (store_dir, POSTFIX)
        if not os.path.exists(self.result_path):
            os.makedirs(self.result_path)
        latest_path = "%s/run-results/latest" % store_dir
        if os.path.exists(latest_path):
            os.remove(latest_path)
        command("ln -s %s %s" % (POSTFIX, latest_path))
        self.mode_path = "%s/%s" % (self.result_path, self.azure_mode.upper())

    def _get_rerun_list(self):
        logging.info("Rerun case list:")
        with open('%s/results.json' % self.job_path, 'r') as f:
            data = f.read()
        result_dict = json.loads(data)
        rerun_list = []
        for case in result_dict["tests"]:
            if str(case["status"]) == 'FAIL' or \
               str(case["status"]) == 'ERROR':
                case_name = case["test"].split(':')[1]
                if case_name not in IGNORE_LIST:
                    rerun_list.append(case_name)
                    logging.info(case_name)
        return rerun_list

    def mk_rerun_yaml(self, rerun_list):
        if self.azure_mode == 'asm':
            remove_node = 'arm'
        else:
            remove_node = 'asm'
        test_rerun_str = """\
test:
    !include : common.yaml
    !include : vm_sizes.yaml
    !include : rerun_cases.yaml
    azure_mode: !mux
        !remove_node : %s
""" % remove_node
        test_rerun_file = "%s/cfg/test_rerun.yaml" % self.avocado_path
        with open(test_rerun_file, 'w') as f:
            f.write(test_rerun_str)
        rerun_cases_file = "%s/cfg/rerun_cases.yaml" % self.avocado_path
        rerun_cases_str = """\
azure_mode: !mux
    %s:
        cases:
            ImgPrepTest.test_00_preparation
            ImgPrepTest.test_03_import_image_to_azure
""" % self.azure_mode
        rerun_cases_str += '            ' + '\n            '.join(rerun_list)
        logging.debug(rerun_cases_str)
        with open(rerun_cases_file, 'w') as f:
            f.write(rerun_cases_str)

    def provision_onpremise(self):
        logging.info("Onpremise provisioning...")
        cmd = "avocado run {0}/tests/01_img_prep.py --multiplex {0}/cfg/provision.yaml".format(self.avocado_path)
        logging.debug(command(cmd, timeout=None, ignore_status=True, debug=True).stdout)
        if self._get_rerun_list():
            logging.error("Onpremise provision failed!")
            sys.exit(1)
        logging.info("Onpremise provision successfully.")
        return 0

    def provision_ondemand(self):
        logging.info("Ondemand provisioning...")
#        cmd = "python {0}/ondemand_provision.py".format(AVOCADO_PATH)
#        ret = command(cmd, timeout=None, ignore_status=True, debug=True)
#        if ret.exit_status != 0:
#            logging.error("Ondemand privision failed!")
#            sys.exit(1)
#        os_disk = ret.stdout
        return ondemand_provision.main()

    def run(self):
        logging.info("=============== Test run begin: %s mode ===============" % self.azure_mode)
        cmd1 = "avocado run %s/tests/*.py --multiplex %s/cfg/test_%s.yaml" % (self.avocado_path, self.avocado_path, self.azure_mode)
        logging.debug(cmd1)
        ret = command(cmd1, timeout=None, ignore_status=True, debug=True)
        logging.debug(ret.stdout)
        run_exitstatus = ret.exit_status
        logging.info("Copy %s to %s" % (self.job_path, self.mode_path))
        shutil.copytree(self.job_path, self.mode_path)
        # Rerun failed cases
        rerun_list = self._get_rerun_list()
        if rerun_list:
            logging.info("Rerun failed cases")
            self.mk_rerun_yaml(rerun_list)
            ret_rerun = command("avocado run %s/tests/*.py --multiplex %s/cfg/test_rerun.yaml" %
                                (self.avocado_path, self.avocado_path),
                                timeout=None, ignore_status=True, debug=True)
            logging.debug(ret_rerun.stdout)
            run_exitstatus += ret_rerun.exit_status
            shutil.copytree(self.job_path, "%s/rerun_result" % self.mode_path)
        logging.info("=============== Test run end:   %s mode ===============" % self.azure_mode)
        return run_exitstatus


def provision():
    if TYPE == "onpremise":
        return Run().provision_onpremise()
    elif TYPE == "ondemand":
        return Run().provision_ondemand()


def runtest():
    if "asm" not in AZURE_MODE and "arm" not in AZURE_MODE:
        parser.print_help()
        parser.error("%s is not azure mode." % AZURE_MODE)
    else:
        logging.info("Azure Mode: %s" % AZURE_MODE)
        run_exitstatus = 0
        if "asm" in AZURE_MODE:
            asm_run = Run("asm")
            run_exitstatus += asm_run.run()
        if "arm" in AZURE_MODE:
            arm_run = Run("arm")
            run_exitstatus += arm_run.run()
        return run_exitstatus


def import_result():
    if SUBMIT_RESULT:
        # Parse polarion_config.yaml
        config_file = '%s/cfg/polarion_config.yaml' % AVOCADO_PATH
        if not os.path.exists(config_file):
            logging.error("No config file: %s" % config_file)
            sys.exit(1)
        with open(config_file) as f:
            conf = yaml.load(f.read())
        # Set testrun prefix
        if TYPE and TYPE.lower() != "none":
            runtype = ' ' + TYPE
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
            rhel_version=conf["RHEL_VERSION"].replace('.', '_'))
        xunit_project = "rhel{0}".format(conf["PROJECT"].split('.')[0])
        # Get results path
        result_path = conf["RESULT_PATH"]
        # Main process
        logging.info("=============== Combine ASM/ARM results ===============")
        ret = command("/usr/bin/python {0}/tools/combine_azuremode_result.py -p {1} -o {1}/merged_result.xml".format(AVOCADO_PATH, result_path), debug=True).exit_status
        logging.info("=============== Convert avocado result to xUnit format ===============")
        ret += command("/usr/bin/python {0}/xen-ci/utils/convert_result2xunit.py -f {1}/merged_result.xml -t azure -p {2} -r {3} -o {1}/xUnit.xml".format(AVOCADO_PATH, result_path, xunit_project, TESTRUN_PREFIX), debug=True).exit_status
        logging.info("=============== Import result to polarion ===============")
#        ret = command("/usr/bin/python %s/tools/import_JunitResult2Polarion.py" % AVOCADO_PATH, debug=True).exit_status
        ret += command("curl -k -u {0}_machine:polarion -X POST -F file=@{1}/xUnit.xml https://polarion.engineering.redhat.com/polarion/import/xunit".format(result_path, xunit_project), debug=True).exit_status
        logging.info("Import result successful")
        return ret
    else:
        logging.info("Do not submit result to polarion.")
        return 0


def teardown():
    logging.info("=============== Teardown ===============")
    ret = command("avocado run {0}/tests/01_img_prep.py: --multiplex {0}/cfg/provision.yaml".format(AVOCADO_PATH))
    logging.info("Teardown finished.")
    return ret


def _get_osdisk(osdisk_path=OSDISK_PATH):
    if not options.osdisk:
        if os.path.isfile(osdisk_path):
            with open(osdisk_path, 'r') as f:
                osdisk = f.read().strip("\n")
            if ".vhd" not in osdisk:
                logging.error("osdisk format is wrong.")
                sys.exit(1)
        else:
            logging.error("No osdisk")
            sys.exit(1)
    else:
        osdisk = options.osdisk
    return osdisk


def main():
    # modify /etc/avocado/avocado.conf
    config()
    # Create configuration files
    if TYPE == "onpremise":
        logging.info("Creating configuration files...")
        command("/usr/bin/python {0}/create_conf.py --type=onpremise".format(AVOCADO_PATH), debug=True)
        logging.info("Configuration files are created.")
        # Run main process
        if PROVISION_ONLY:
            logging.info("Provision only")
            sys.exit(provision())
        elif RUN_ONLY:
            logging.info("Run test only")
            sys.exit(runtest() or teardown())
        elif IMPORT_ONLY:
            logging.info("Import result only")
            sys.exit(import_result())
#        elif TEARDOWN:
#            logging.info("Teardown only")
#            sys.exit(teardown())
        else:
            sys.exit(provision() or runtest() or import_result() or teardown())
    elif TYPE == "ondemand":
        # Run main process
        if os.path.isfile(OSDISK_PATH):
            os.remove(OSDISK_PATH)
        if PROVISION_ONLY:
            logging.info("Provision only")
            command("/usr/bin/python {0}/create_conf.py --type=ondemand --provision-only"
                    .format(AVOCADO_PATH), debug=True)
            sys.exit(provision())
        elif RUN_ONLY:
            logging.info("Run test only")
            osdisk = _get_osdisk()
            command("/usr/bin/python {0}/create_conf.py --type=ondemand --osdisk={1} --run-only"
                    .format(AVOCADO_PATH, osdisk), debug=True)
            sys.exit(runtest() or teardown())
        elif IMPORT_ONLY:
            logging.info("Import result only")
            command("/usr/bin/python {0}/create_conf.py --type=ondemand --import-only"
                    .format(AVOCADO_PATH), debug=True)
            sys.exit(import_result())
#        elif TEARDOWN:
#            command("/usr/bin/python {0}/create_conf.py --type=ondemand --osdisk=empty"
#                    .format(AVOCADO_PATH), debug=True)
#            logging.info("Teardown only")
#            sys.exit(teardown())
        else:
            command("/usr/bin/python {0}/create_conf.py --type=ondemand --provision-only"
                    .format(AVOCADO_PATH), debug=True)
            ret = 0
            ret += provision()
            osdisk = _get_osdisk()
            command("/usr/bin/python {0}/create_conf.py --type=ondemand --osdisk={1}"
                    .format(AVOCADO_PATH, osdisk), debug=True)
            ret += runtest()
            ret += import_result()
            ret += teardown()
            sys.exit(ret)
    elif TYPE == "customize":
        logging.info("Creating configuration files...")
        command("/usr/bin/python {0}/create_conf.py --type=customize".format(AVOCADO_PATH), debug=True)
        logging.info("Configuration files are created.")
        sys.exit(runtest() or import_result())
    else:
        parser.print_help()
        parser.error("Wrong type!")


if __name__ == "__main__":
    usage = "usage: %prog [options] [-m <mode>]"
    parser = OptionParser(usage)
    parser.add_option('-p', '--provision-only', dest='provision_only', default=False, action='store_true',
                      help='Only run provision. Do not run test cases.')
    parser.add_option('-r', '--run-only', dest='run_only', default=False, action='store_true',
                      help='Only run test cases. Do not provision.')
    parser.add_option('-i', '--import-only', dest='import_only', default=False, action='store_true',
                      help='Only import the latest result to polarion. Do not run tests.')
    parser.add_option('-T', '--teardown', dest='teardown', default=False, action='store_true',
                      help='Delete the VMs and images that generated in this test run.')
    parser.add_option('-m', '--mode', dest='azure_mode', default='asm,arm', action='store',
                      help='The azure modes you want to run test cases(asm,arm). Separate with comma. '
                           'If not set, run both asm and arm mode.',
                      metavar='AZUREMODE')
    parser.add_option('-o', '--osdisk', dest='osdisk', action='store',
                      help='The VHD OS disk name(e.g.RHEL-7.3-20161019.0-wala-2.2.0-2.vhd)', metavar='OSDISK.vhd')
    parser.add_option('-t', '--type', dest='type', action='store',
                      help='The type of the test. Default value is onpremise. '
                           '(onpremise/ondemand/customize)', metavar='TYPE')

    options, args = parser.parse_args()
    AZURE_MODE = options.azure_mode.lower()
    PROVISION_ONLY = options.provision_only
    RUN_ONLY = options.run_only
    IMPORT_ONLY = options.import_only
    TEARDOWN = options.teardown
    TYPE = options.type if options.type else yaml.load(file('%s/config.yaml' % AVOCADO_PATH)).get("type", "onpremise")

    main()
