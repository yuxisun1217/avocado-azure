import pdb
import re
import os
import sys
import time
import shutil
import json
import yaml
from optparse import OptionParser
from azuretest.utils_misc import *

LOGFILE = "/tmp/run-avocado-azure.log"
POSTFIX = time.strftime("%Y%m%d%H%M")
AVOCADO_PATH = os.path.split(os.path.realpath(__file__))[0]
IGNORE_LIST = ["SettingsTest.test_reset_access_successively",
               "SettingsTest.test_reset_pw_after_capture"]
#UPSTREAM = yaml.load(file('%s/config.yaml' % AVOCADO_PATH))["upstream"]
SUBMIT_RESULT = yaml.load(file('%s/config.yaml' % AVOCADO_PATH))["submit_result"]


def log(msg):
    prefix = time.strftime("%Y-%m-%d %H:%M:%S ")
    msg = prefix + msg + '\n'
    with open(LOGFILE, 'a') as f:
        f.write(msg)

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
        log("Rerun case list:")
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
                    log(case_name)
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
        log(rerun_cases_str)
        with open(rerun_cases_file, 'w') as f:
            f.write(rerun_cases_str)

    def provision(self):
        log("Provisioning...")
        cmd = "avocado run {0}/tests/01_img_prep.py --multiplex {0}/cfg/provision.yaml".format(self.avocado_path)
        log(command(cmd, timeout=None, ignore_status=True, debug=True).stdout)
        if self._get_rerun_list():
            log("Error: Provision Failed!")
            sys.exit(1)
        log("Provision successful.")
        return 0

    def run(self):
        log("=============== Test run begin: %s mode ===============" % self.azure_mode)
        cmd1 = "avocado run %s/tests/*.py --multiplex %s/cfg/test_%s.yaml" % (self.avocado_path, self.avocado_path, self.azure_mode)
        log(cmd1)
        log(command(cmd1, timeout=None, ignore_status=True, debug=True).stdout)
        log("Copy %s to %s" % (self.job_path, self.mode_path))
        shutil.copytree(self.job_path, self.mode_path)
        # Rerun failed cases
        rerun_list = self._get_rerun_list()
        if rerun_list:
            log("Rerun failed cases")
            self.mk_rerun_yaml(rerun_list)
            log(command("avocado run %s/tests/*.py --multiplex %s/cfg/test_rerun.yaml" %
                        (self.avocado_path, self.avocado_path),
                        timeout=None, ignore_status=True, debug=True).stdout)
            shutil.copytree(self.job_path, "%s/rerun_result" % self.mode_path)
        log("=============== Test run end:   %s mode ===============" % self.azure_mode)


def provision():
    Run().provision()


def runtest():
    if "asm" not in AZURE_MODE and "arm" not in AZURE_MODE:
        parser.print_help()
        parser.error("%s is not azure mode." % AZURE_MODE)
    else:
        log("Azure Mode: %s" % AZURE_MODE)
        if "asm" in AZURE_MODE:
            asm_run = Run("asm")
            asm_run.run()
        if "arm" in AZURE_MODE:
            arm_run = Run("arm")
            arm_run.run()


def import_result():
    if SUBMIT_RESULT:
        log("=============== Import result to polarion ===============")
        command("/usr/bin/python %s/tools/import_JunitResult2Polarion.py" % AVOCADO_PATH, debug=True)
        log("Import result successful")
    else:
        log("Do not submit result to polarion.")
    return 0



def main():
    # modify /etc/avocado/avocado.conf
    config()
    # Create configuration files
    log("Creating common.yaml and azure_image_prepare.yaml...")
    command("/usr/bin/python %s/create_conf.py" % AVOCADO_PATH, debug=True)
    log("common.yaml and azure_image_prepare.yaml are created.")
    if PROVISION_ONLY:
        log("Provision only")
        sys.exit(provision())
    elif RUN_ONLY:
        log("Run test only")
        sys.exit(runtest())
    elif IMPORT_ONLY:
        log("Import result only")
        sys.exit(import_result())
    else:
        provision()
        runtest()
        import_result()


if __name__ == "__main__":
    usage = "usage: %prog [options] [-m <mode>]"
    parser = OptionParser(usage)
    parser.add_option('-p', '--provision-only', dest='provision_only', default=False, action='store_true',
                      help='Only run provision. Do not run test cases.')
    parser.add_option('-r', '--run-only', dest='run_only', default=False, action='store_true',
                      help='Only run test cases. Do not provision.')
    parser.add_option('-i', '--import-only', dest='import_only', default=False, action='store_true',
                      help='Only import the latest result to polarion. Do not run tests.')
    parser.add_option('-m', '--mode', dest='azure_mode', default='asm,arm', action='store',
                      help='The azure modes you want to run test cases(asm,arm). Separate with comma. '
                           'If not set, run both asm and arm mode.',
                      metavar='AZUREMODE')

    options, args = parser.parse_args()
    AZURE_MODE = options.azure_mode.lower()
    PROVISION_ONLY = options.provision_only
    RUN_ONLY = options.run_only
    IMPORT_ONLY = options.import_only

    main()
