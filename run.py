import pdb
import re
import os
import sys
import time
import shutil
import json
import yaml
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
            line = "test_dir = %s/tests\n" % AVOCADO_AZURE
        elif re.findall(comp_data, line):
            line = "data_dir = %s/data\n" % AVOCADO_AZURE
        elif re.findall(comp_logs, line):
            line = "logs_dir = %s/job-results\n" % AVOCADO_AZURE
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
#        rerun_list = self._get_rerun_list()
        rerun_cases_str += '            ' + '\n            '.join(rerun_list)
        log(rerun_cases_str)
        with open(rerun_cases_file, 'w') as f:
            f.write(rerun_cases_str)

    def run(self):
        log("=============== Test run begin: %s mode ===============" % self.azure_mode)
#        log(command("avocado run %s/tests/*.py --multiplex %s/cfg/test_%s%s.yaml" %
#                    (self.avocado_path, self.avocado_path, self.azure_mode, self.upstream),
#                    timeout=None, ignore_status=True, debug=True).stdout)
        cmd1 = "avocado run %s/tests/*.py --multiplex %s/cfg/test_%s.yaml" % (self.avocado_path, self.avocado_path, self.azure_mode)
#        log(command("avocado run %s/tests/*.py --multiplex %s/cfg/test_%s.yaml" %
#                    (self.avocado_path, self.avocado_path, self.azure_mode),
#                    timeout=None, ignore_status=True, debug=True).stdout)
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


def main():
    # modify /etc/avocado/avocado.conf
    config()
    # Create configuration files
    log("Creating common.yaml and azure_image_prepare.yaml...")
    command("/usr/bin/python %s/create_conf.py" % AVOCADO_PATH, debug=True)
    log("common.yaml and azure_image_prepare.yaml are created.")
    # Run test cases
    asm_flag = False
    arm_flag = False
    if len(sys.argv) > 1:
        if "asm" in sys.argv[1:]:
            asm_flag = True
        if "arm" in sys.argv[1:]:
            arm_flag = True
    else:
        asm_flag = True
        arm_flag = True
    log("ASM mode: %s;  ARM mode: %s" % (asm_flag, arm_flag))
    if asm_flag:
        asm_run = Run("asm")
        asm_run.run()
    if arm_flag:
        arm_run = Run("arm")
        arm_run.run()
    # Upload result to polarion
    if SUBMIT_RESULT:
        log("=============== Begin to sumbit result to polarion ===============")
        command("/usr/bin/python %s/tools/import_JunitResult2Polarion.py" % AVOCADO_PATH, debug=True)
    else:
        log("Do not submit result to polarion.")
    log("=============== Finished ===============")

#    latest_path = "%s/run-results/latest" % AVOCADO_PATH
#    if os.path.exists(latest_path):
#        os.remove(latest_path)
#    command("ln -s %s %s" % (POSTFIX, latest_path))


if __name__ == "__main__":
    main()
