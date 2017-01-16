#!/usr/bin/python
import os
import sys
import urllib2
import time
import re
import shutil
import platform
import subprocess
import string
import hashlib
import pwd
import yaml

AzureImagePrepareConf = """\
#
# Azure Image Prepare Script Configuration
#

Project: 7.3                                # Specify the project.
Version:                                    # Specify a RHEL version you need. If set, the Project will be ignored. (e.g.)Version: RHEL-6.8-20160413.0
WalaVersion:                                # Specify a WALinuxAgent rpm version. (e.g.)WalaVersion: 2.0.16-1. If empty, download the latest version.
Upstream: False                             # If get WALinuxAgent from upstream(github), set it to True; else, set it to False
Baseurl: http://download.eng.pek2.redhat.com/rel-eng/  # The URL to download original iso. Must be end with "/".
MainDir: /home/autotest/                    # The main folder to store original iso. Must be end with "/".
TmpDir: /home/tmp/azure/                    # Temporary folder to store the temporary files, such as new iso and mount point. Must be end with "/".
Logfile: /tmp/azure_image_prepare.log       # Logfile
Verbose: n                                  # Enable verbose logs
ImageSize: 10                               # The VM image disk size in GB
Tag:                                        # The extra tag string for the vhd file name
"""


class ConfigurationProvider(object):
    """
    Parse and store key:values in azure_image_prepare.yaml
    """

    def __init__(self, configfile_path):
        self.values = dict()
        if configfile_path is None:
            configfile_path = "%s/azure_image_prepare.yaml" % p.realpath
        if not os.path.isfile(configfile_path):
            Warn("Missing configuration in {0}".format(configfile_path))
            self.setconf(configfile_path)
        try:
#            for line in GetFileContents(configfile_path).split('\n'):
#                if not line.startswith("#") and "=" in line:
#                    parts = line.split()[0].split('=')
#                    value = parts[1].strip("\" ")
#                    if value != "None":
#                        self.values[parts[0]] = value
#                    else:
#                        self.values[parts[0]] = None
            with open(configfile_path) as f:
                self.values = yaml.load(f)
        except:
            Error("Unable to parse {0}".format(configfile_path))
            raise
        return

    def setconf(self, configfile_path):
        try:
            os.makedirs(os.path.dirname(configfile_path))
        except:
            pass
        return SetFileContents(configfile_path, AzureImagePrepareConf)

    def get(self, key):
        return self.values.get(key) if self.values.get(key) != "None" else None


class Params(object):
    """
    Global parameters class
    """

    def __init__(self, configfile_path, realpath):
        self.realpath = realpath
        c = ConfigurationProvider(configfile_path)
        self.Project = str(c.get("Project"))
        self.Version = c.get("Version")
        if self.Version is not None:
            self.Project = self.Version.split('-')[1]
        self.WalaVersion = c.get("WalaVersion")
        # Cannot use bool(xxx) to convert string to bool type!
        self.Upstream = c.get("Upstream")
        Log("Upstream: %s" % self.Upstream)
        self.TmpDir = c.get("TmpDir")
        main_dir = c.get("MainDir")
        self.Baseurl = c.get("Baseurl")
        get_verbose = c.get("Verbose")
        self.Logfile = c.get("Logfile")
        self.ImageSize = int(c.get("ImageSize"))
        self.Tag = c.get("Tag")
        if get_verbose is not None and get_verbose.lower().startswith("y"):
            myLogger.verbose = True
            # self.ConfigDir=os.path.dirname(configfile_path)+"/"
        self.walaDir = main_dir + "wala/RHEL-" + self.Project[0] + "/"
        tool_path = self.realpath + "tools/azure_image_prepare/"
        self.ksDir = tool_path + "ks/"
        self.toolsDir = tool_path + "tools/"
        self.rhuiDir = tool_path + "rhui/"
        self.patchDir = tool_path + "patch/"
        self.vhdDir = main_dir + "vhd/"
        self.isoDir = main_dir + "iso/RHEL-" + self.Project + "/"
        self.newisoDir = self.TmpDir + "newiso/"
        self.srcksPath = self.ksDir + "RHEL-" + self.Project.split('.')[0] + ".cfg"
        self.isoName = ""  # ISO file name without postfix(.iso)
        self.walaName = ""  # WALA package name
        self.rpmbuildPath = "/root/rpmbuild"


class Logger(object):
    def __init__(self, filepath, verbose=False):
        """
        Construct an instance of Logger.
        """
        self.verbose = verbose
        self.filepath = filepath

    def Log(self, message):
        """
        Write 'message' to logfile.
        """
        timestr = time.strftime('[%Y-%m-%d %H:%M:%S] ')
        if self.filepath:
            try:
                with open(self.filepath, "a") as F:
                    message = filter(lambda x: x in string.printable, message)
                    F.write(timestr + message.encode('ascii', 'ignore') + "\n")
            except IOError, e:
                print e
                pass

    def LogIfVerbose(self, message):
        if self.verbose:
            Log(message)
        else:
            pass

    def LogWithPrefix(self, prefix, message):
        """
        Prefix each line of 'message' with 'prefix'.
        """
        for line in message.split('\n'):
            line = prefix + line
            self.Log(line)

    def Warn(self, message):
        """
        Prepend the text "WARNING:" to the prefix for each line in 'message'.
        """
        self.LogWithPrefix("WARNING:", message)

    def Error(self, message):
        """
        Prepend the text "ERROR:" to the prefix for each line in 'message'.
        """
        self.LogWithPrefix("ERROR:", message)


def LoggerInit(logfile_path, verbose=False):
    """
    Create log object and export its methods to global scope.
    """
    global Log, LogWithPrefix, LogIfVerbose, Error, Warn, myLogger
    l = Logger(logfile_path, verbose)
    Log, LogWithPrefix, LogIfVerbose, Error, Warn, myLogger = l.Log, l.LogWithPrefix, l.LogIfVerbose, l.Error, l.Warn, l


def ErrorAndExit(message):
    """
    Error(msaage);sys.exit(1)
    """
    Error(message + ". Exit.")
    sys.exit(1)


def GetFileContents(filepath, asbin=False):
    """
    Read and return contents of 'filepath'.
    """
    mode = 'r'
    if asbin:
        mode += 'b'
    try:
        with open(filepath, mode) as F:
            c = F.read()
    except IOError, e:
        Error('Reading from file ' + filepath + 'failed. Exception: ' + str(e))
        return None
    return c


def SetFileContents(filepath, contents):
    """
    Write 'contents' to 'filepath'.
    """
    if type(contents) == str:
        contents = contents.encode('latin-1', 'ignore')
    try:
        with open(filepath, "wb+") as F:
            F.write(contents)
    except (IOError, TypeError) as e:
        Error('Writing to file ' + filepath + ' failed. Exception: ' + str(e))
        return None
    return 0


def Run(cmd, chk_err=True):
    """
    Calls RunGetOutput on 'cmd', returning only the return code.
    If chk_err=True then errors will be reported in the log.
    If chk_err=False then errors will be suppressed from the log.
    """
    retcode, out = RunGetOutput(cmd, chk_err)
    return retcode


def RunGetOutput(cmd, chk_err=True, log_cmd=True):
    """
    Wrapper for subprocess.check_output.
    Execute 'cmd'.  Returns return code and STDOUT, trapping expected exceptions.
    Reports exceptions to Error if chk_err parameter is True
    """
    if log_cmd:
        LogIfVerbose(cmd)
    try:
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=True)
    except subprocess.CalledProcessError, e:
        if chk_err and log_cmd:
            Error('CalledProcessError.  Error Code is ' + str(e.returncode))
            Error('CalledProcessError.  Command string was ' + e.cmd)
            Error('CalledProcessError.  Command result was ' + (e.output[:-1]).decode('latin-1'))
        return e.returncode, e.output.decode('latin-1')
    return 0, output.decode('latin-1')


def CheckPlatform():
    """
    This script must be run on RHEL6 or RHEL7.
    """
    distro = platform.linux_distribution(full_distribution_name=0)[0]
    Log("Platform: %s" % distro)
    if distro != 'redhat':
        ErrorAndExit("Must run qemu-img on RHEL")


def ChangeOwner(filepath, user):
    """
    Lookup user.  Attempt chown 'filepath' to 'user'.
    """
    u = None
    try:
        u = pwd.getpwnam(user)
    except:
        pass
    if u is not None:
        os.chown(filepath, u[2], u[3])


def CreateDir(dirpath, user=None, mode=0755):
    """
    Attempt os.makedirs, catch all exceptions.
    Call ChangeOwner afterwards.
    """
    if not user:
        user = RunGetOutput("whoami")[1].split('\n')
    LogIfVerbose("Try to create " + dirpath)
    if os.path.exists(dirpath):
        LogIfVerbose(dirpath + " already exists.")
        return True
    else:
        try:
            os.makedirs(dirpath, mode)
        except Exception, e:
            Error("Cannot make dir " + dirpath + ". Exception: " + str(e))
            return False
        ChangeOwner(dirpath, user)
        LogIfVerbose("Create " + dirpath + " successfully.")
        return True


def CheckFileExist(filepath, ifexit=True):
    """
    Check if file exists. If not, save log and exit.
    """
    if os.path.exists(filepath) == False:
        if ifexit:
            ErrorAndExit(filepath + " doesn't exist")
        else:
            Error(filepath + " doesn't exist.")
            return False
    return True


def CheckFileNotExist(filepath, ifexit=True):
    """
    If file exists, remove it.
    """
    if os.path.exists(filepath):
        Warn(filepath + " already exists. Remove it.")
        try:
            os.remove(filepath)
        except Exception, e:
            if ifexit:
                ErrorAndExit("Cannot remove " + filepath + ". Exception: " + str(e))
            else:
                Error("Cannot remove " + filepath + ". Exception: " + str(e))
                return False
    return True


def _hashfile(afile, hasher, blocksize=65536):
    buf = afile.read(blocksize)
    while len(buf) > 0:
        hasher.update(buf)
        buf = afile.read(blocksize)
    return hasher.hexdigest()


def _copyfile(src, dst, ftype="file"):
    CheckFileExist(src)
    try:
        if ftype == "tree":
            shutil.copytree(src, dst)
        else:
            shutil.copy(src, dst)
    except Exception, e:
        ErrorAndExit("Cannot copy {0} to {1}. Exception: {2}".format(src, dst, str(e)))
    Log("Copy {0} to {1} successfully.".format(src, dst))


###### Download the latest build ######

def calculate_md5(afile):
    return _hashfile(open(afile, 'rb'), hashlib.md5())


def get_latest_build():
    """
    Make a dictionary to store project:version pairs.
    """
    LogIfVerbose("Getting RHEL build dictionary...")
    LogIfVerbose("Open " + p.Baseurl)
    try:
        alldata = urllib2.urlopen(p.Baseurl).read()
    except urllib2.HTTPError, e:
        ErrorAndExit("Cannot open " + p.Baseurl + ". Exception: " + str(e))
    r = re.compile('RHEL-\d.\d-\d+.\d')
    tree_list = r.findall(alldata)
    tree_list = list(set(tree_list))
    tree_project_dict = {}
    tree_version_dict = {}
    for tree in tree_list:
        _, tree_project, tree_version = tree.split('-')
        tree_date, tree_subversion = tree_version.split('.')
        tree_project_dict.setdefault(tree_project, []).append(tree_date)
        tree_version_dict.setdefault(tree_date, []).append(tree_subversion)
    max_dict = {}
    for tree_project in tree_project_dict.keys():
        max_date = max(list(tree_project_dict[tree_project]))
        max_version = max(list(tree_version_dict[max_date]))
        max_dict.setdefault(tree_project, []).append('RHEL-' + tree_project + '-' + max_date + '.' + max_version)
    return max_dict


def download_iso(version=None):
    """
    Call get_latest_build()
    Check md5. If not match, download again.
    return iso fullpath.
    """
    if version is not None:
        latest_build = version
    elif p.Project != "":
        latest_build = get_latest_build()[p.Project][0]
    else:
        ErrorAndExit("There must be Version or Project parameter in the azure_image_prepare.yaml")
    iso_name = latest_build + '-Server-x86_64-dvd1.iso'
    iso_url = p.Baseurl + latest_build + '/compose/Server/x86_64/iso/' + iso_name
    md5_url = iso_url + '.MD5SUM'
#    iso_folder = p.MainDir + 'iso/RHEL-' + p.Project + '/'
    iso_folder = p.isoDir
    iso_fullpath = iso_folder + iso_name
    CreateDir(iso_folder)
    try:
        md5url = urllib2.urlopen(md5_url)
    except urllib2.HTTPError, e:
        ErrorAndExit("Cannot open " + md5_url + ". Exception: " + str(e))
    md5 = re.findall(re.compile('[0-9a-z]{32}'), md5url.read())[0]
    while True:
        if os.path.isfile(iso_fullpath) is False:
            outf = open(iso_fullpath, 'wb')
            try:
                f = urllib2.urlopen(iso_url)
            except urllib2.HTTPError, e:
                ErrorAndExit("Cannot open " + iso_url + ". Exception: " + str(e))
            #            f=urllib2.urlopen(md5_url)
            c = 0
            Log("Download " + iso_fullpath + " begin.")
            while True:
                s = f.read(1024 * 1024 * 10)
                if len(s) == 0:
                    break
                outf.write(s)
                c += len(s)
                LogIfVerbose("Downloading " + str(c))
            Log("Download " + iso_fullpath + " finished.")
        else:
            Warn(iso_fullpath + " already exists.")
        time.sleep(1)
        Log("Checking MD5...")
        realmd5 = calculate_md5(iso_fullpath)
        LogIfVerbose("Target MD5: " + md5)
        LogIfVerbose("Real MD5:   " + realmd5)
        if realmd5 == md5:
            Log("MD5 matches. ISO is ready.")
            break
        Error("MD5 does not match. Download again.")
        os.remove(iso_fullpath)
    return 0


def get_newest_local_isoname():
    """
    Return the newest version iso name in the p.isoDir.
    """
    version_dict = {}
    filelist = os.listdir(p.isoDir)
    for filename in filelist:
        version = filename.split("-")[2]
        version_dict.setdefault(version.split('.')[0], []).append(version.split('.')[1])
    if not version_dict:
        p.isoName = None
        return None
    max_date = max(list(version_dict.keys()))
    max_subversion = max(list(version_dict[max_date]))
    p.isoName = "RHEL-" + p.Project + "-" + max_date + "." + max_subversion + "-Server-x86_64-dvd1"
    return p.isoName


def get_latest_wala_downstream():
    """
    Get the latest wala build
    """
    if float(p.Project) < 7.0:
        brewcmd = "brew latest-build extras-rhel-6 WALinuxAgent|grep WALinuxAgent|awk '{print $1}'"
    else:
        brewcmd = "brew latest-build extras-rhel-" + str(p.Project) + " WALinuxAgent|grep WALinuxAgent|awk '{print $1}'"
    rcode, walabuild = RunGetOutput(brewcmd)
    if rcode != 0:
        ErrorAndExit("Cannot get the latest wala build")
    #    For brewkoji-1.9-1
    #    return walabuild.strip('\n')+".noarch.rpm"
    return walabuild.strip('\n')


def download_wala_downstream(version=None):
    """
    Download the latest wala package from brew.
    """
    if version != None:
        #        For brewkoji-19-1
        #        p.walaName = "WALinuxAgent-%s.el%s.noarch.rpm" % (version, str(p.Project).split('.')[0])
        p.walaName = "WALinuxAgent-%s.el%s" % (version, str(p.Project).split('.')[0])
    else:
        p.walaName = get_latest_wala_downstream()
    CreateDir(p.walaDir)
    for walafile in os.listdir(p.walaDir):
        if walafile.find(p.walaName + ".noarch.rpm") != -1:
            Log("%s.noarch.rpm already exists." % p.walaName)
            return 0
    os.chdir(p.walaDir)
    #    For brewkoji-19-1
    #    Run("brew download-build --rpm "+p.walaName)
    if Run("brew download-build --arch=noarch %s" % p.walaName) != 0:
        ErrorAndExit("No such WALA build: %s" % p.walaName)
    Log("Download " + p.walaDir + p.walaName + ".noarch.rpm successfully.")
    return 0


def get_latest_wala_upstream():
    """
    Get the latest wala build from upstream
    """
    cmd = "curl https://github.com/Azure/WALinuxAgent/releases/latest"
    rcode, output = RunGetOutput(cmd)
    if rcode != 0:
        ErrorAndExit("Cannot get the latest upstream wala build")
    walabuild = re.compile('.*tag/(.*)\">').search(output).groups()[0]
    return walabuild
#    wala_uri = "https://api.github.com/repos/Azure/WALinuxAgent/releases/latest"
#    body = urllib2.urlopen(wala_uri).read()
#    wala_json = json.loads(body)
#    if not wala_json["name"]:
#        ErrorAndExit("Cannot get the latest upstream wala build")
#    walabuild = wala_json["name"]
#    return walabuild


def download_wala_upstream(version=None):
    """
    Download the latest wala package from brew.
    """
    if version is None:
        tag = get_latest_wala_upstream()
        version = re.compile('\d*\.\d*\.\d*').findall(tag)[0]
    else:
        version = re.compile('\d*\.\d*\.\d*').findall(version)[0]
        tag = "WALinuxAgent-%s-0" % version
        x, y, z = version.split('.')
        if int(x) >= 2:
            if int(y) >= 1:
                if int(z) >= 2:
                    tag = 'v' + version
    p.walaName = "WALinuxAgent-%s-0.el%s" % (version, p.Project.split('.')[0])
    wala_fullpath = "%s.noarch.rpm" % (p.walaDir+p.walaName)
    CreateDir(p.walaDir)
    if os.path.isfile(wala_fullpath):
        Log("%s already exists." % wala_fullpath)
        return 0
    os.chdir(p.TmpDir)
    Log("Change current path to %s" % p.TmpDir)
    if Run("wget -O WALinuxAgent-%s.tar.gz https://github.com/Azure/WALinuxAgent/archive/v%s.tar.gz" %
           (version, version)) != 0:
        ErrorAndExit("No such WALA build %s" % tag)
    Run("mv WALinuxAgent-%s.tar.gz %s/SOURCES/" % (version, p.rpmbuildPath))
    with open("%s/WALinuxAgent-template.spec" % p.realpath, 'r') as f:
        spec_data = f.read()
    with open("%s/SPECS/WALinuxAgent-upstream.spec" % p.rpmbuildPath, 'w') as f:
        f.write(spec_data.replace("upstream_version", version))
    Run("/usr/bin/cp -f {0}* {1}/SOURCES/".format(p.patchDir, p.rpmbuildPath))
    # Use mock instead of rpmbuild to make rpm package
    main_project = p.Project.split('.')[0]
    Run("rpmbuild -bs %s/SPECS/WALinuxAgent-upstream.spec" % p.rpmbuildPath)
    src_name = RunGetOutput("find {0}/SRPMS/WALinuxAgent-{1}-0.*.src.rpm"
                            .format(p.rpmbuildPath, version))[1].strip('\n').split('/')[-1]
    Log(src_name)
    Run("mv {0}/SRPMS/{1} {2}".format(p.rpmbuildPath, src_name, p.TmpDir))
    Run("runuser -l test -c 'mock -r epel-{0}-x86_64 {1}{2}'"
        .format(main_project, p.TmpDir, src_name))
    Run("mv /var/lib/mock/epel-{0}-x86_64/result/{1}.noarch.rpm {2}"
        .format(main_project, p.walaName, wala_fullpath))
    time.sleep(0.5)
    if os.path.isfile(wala_fullpath):
        Log("Download %s successfully." % wala_fullpath)
    else:
        ErrorAndExit("Download %s failed." % wala_fullpath)
    return 0

# Alias get_latest_wala and download_wala to support both upstream and downstream
def get_latest_wala():
    if p.Upstream:
        return get_latest_wala_upstream()
    else:
        return get_latest_wala_downstream()

def download_wala(version=None):
    if p.Upstream:
        return download_wala_upstream(version)
    else:
        return download_wala_downstream(version)

def rhel_build():
    if p.Version is not None:
        rhel_build = p.Version
    else:
        rhel_build = get_latest_build()[p.Project][0]
    Log("RHEL build: %s" % rhel_build)
    return rhel_build

def wala_build():
    if p.WalaVersion is not None:
        wala_build = p.WalaVersion
    else:
        #                wala_build = get_latest_wala().replace('WALinuxAgent-', '')
        wala_build = re.compile('\d*\.\d*\.\d*-?\d?').findall(get_latest_wala())[0]
    Log("WALA version: %s" % wala_build)
    return wala_build


###### Install ######
def copy2iso(newiso_mount):
    # Copy ks file to newiso
    _copyfile(p.srcksPath, newiso_mount+"ks.cfg")
    # Copy WALinuxAgent package to newiso
    download_wala(p.WalaVersion)
    wala_fullname = p.walaName+".noarch.rpm"
    _copyfile(p.walaDir+wala_fullname, newiso_mount+wala_fullname)
    # Copy tools(fio,iperf3) to newiso
    _copyfile(p.toolsDir, newiso_mount+"tools/", ftype="tree")
    # Copy RHUI package to newiso
    rhui_fullpath = RunGetOutput("ls {0}rhui-azure-rhel{1}*.rpm"
                                 .format(p.rhuiDir, p.Project.split('.')[0]))[1].strip('\n')
    _copyfile(rhui_fullpath, newiso_mount+os.path.basename(rhui_fullpath))
    Log("Copy files to {0} successfully.".format(newiso_mount))


def mk_iso(iso_path, newiso_path):
    """
    Modify isolinux.cfg. Copy WALA package, tools, ks.cfg in. Make new iso.
    """
    if (iso_path == None) or (os.path.isfile(iso_path) == False):
        ErrorAndExit("No RHEL iso. Please download again")
    iso_mount = p.TmpDir + 'iso/'
    newiso_mount = p.TmpDir + 'newiso/'
    isolinux = newiso_mount + 'isolinux/isolinux.cfg'
    CreateDir(iso_mount)
    # Mount origional iso and copy to new path.
    retcode, out = RunGetOutput("mount -o loop " + iso_path + " " + iso_mount)
    if retcode is False and out.find("mounting read-only") == -1:
        ErrorAndExit("Cannot mount " + iso_path + " to " + iso_mount)
    Log("Copying iso to newiso...")
    _copyfile(iso_mount, newiso_mount, ftype="tree")
    Run("umount " + iso_mount)
    # Modify isolinux.cfg. Add ks=cdrom.
    CheckFileExist(isolinux)
    if float(p.Project) < 7.0:
        Run("sed -i %s\
            -e 's/timeout 600/timeout 30/'\
            -e '/append initrd=/s/$/ ks=cdrom/'" % isolinux)
    elif float(p.Project) >= 7.0:
        Run("sed -i %s\
            -e '/menu[[:space:]][[:space:]]*default/d'\
            -e 's/timeout 600/timeout 30/'\
            -e '/append initrd=/s/$/ ks=cdrom/'\
            -e '/^label linux/{N;s/$/\\n  menu default/}'" % isolinux)
    os.chmod(isolinux, 444)
    # Copy files into newiso
    copy2iso(newiso_mount)
    # Make new iso
    isoinfo = RunGetOutput("isoinfo -d -i " + iso_path)[1]
    m = re.search("Volume id:([^\n]*)", isoinfo)
    volid = m.group(1)[1:]
#    Run("mkisofs -J -R -v -T -V \"" + volid + "\" -o " + newiso_path + " -b isolinux/isolinux.bin -c isolinux/boot.cat -no-emul-boot -boot-load-size 4 -boot-info-table " + newiso_mount)
    Run("mkisofs -J -R -v -T -V \"{0}\" -o {1} -b isolinux/isolinux.bin -c isolinux/boot.cat "
        "-no-emul-boot -boot-load-size 4 -boot-info-table {2}".format(volid, newiso_path, newiso_mount))
    Log("Make " + newiso_path + " successfully.")
    return 0


def mk_qcow2(newiso_path, qcow2_path):
    """
    Install img through kickstart.
    """
    # Create empty qcow2 file
    Log("Install qcow2...")
    Run("qemu-img create %s %dG -f qcow2" % (qcow2_path, p.ImageSize))
    CheckFileExist(qcow2_path)
    # Install image
    Run("virt-install --name walatestimg --ram 1024 --network bridge=virbr0 --vcpus 1 "
        "--cdrom {0} --disk path={1},bus=virtio --noreboot".format(newiso_path, qcow2_path))
    Log("Install qcow2 image successfully.")
    return 0


def qcow2_to_vhd(qcow2_path, vhd_path):
    """
    Convert qcow2 to vhd
    """
    Log("Convert qcow2 to vhd...")
    Run("qemu-img convert -f qcow2 -o subformat=fixed -O vpc %s %s" % (qcow2_path, vhd_path))
    CheckFileExist(vhd_path)
    vhd_size = os.path.getsize(vhd_path)
    target_size = p.ImageSize * 1024 * 1024 * 1024 + 512
    if vhd_size != target_size:
        ErrorAndExit(vhd_path + " file size is wrong. Target: %d Real: %d" % (target_size, vhd_size))
    Log("Make %s successfully." % vhd_path)
    return 0


def Usage():
    """
    Print the usage.
    """
    print("usage: " + sys.argv[0] + " [-check|-all|-downloadwala|-download|-install|-convert|-walabuild|-rhelbuild|-help]")
    return 0


def _umount(mount_path):
    """
    Force umount mount_path
    """
    if os.path.exists(mount_path) and RunGetOutput("mount|grep " + mount_path, chk_err=False)[1] != "":
        Run("fuser -km " + mount_path, chk_err=False)
        time.sleep(0.5)
        Run("umount " + mount_path)


def CheckEnvironment(dir_create_list, exist_file_list):
    """
    Prepare the environment before running.
    """
    ret = 0
    Run("virsh destroy walatestimg", chk_err=False)
    Run("virsh undefine walatestimg", chk_err=False)
    _umount(p.TmpDir + "iso")
    _umount(p.TmpDir + "newiso")
    if os.path.isdir(p.TmpDir):
        try:
            shutil.rmtree(p.TmpDir)
        except Exception, e:
            Error("Cannot remove " + p.TmpDir + ". Error code: " + str(e))
            ret = 1
    Run("rm -rf " + p.TmpDir)
    for dirname in dir_create_list:
        if not CreateDir(dirname):
            ret = 1
    for filename in exist_file_list:
        if not CheckFileExist(filename, False):
            ret = 1
    if ret == 0:
        Log("Environment Check result is True")
    else:
        Log("Environment Check result is False")
    return ret


def Download():
    return download_iso(p.Version)


def Download_wala():
    return download_wala(p.WalaVersion)


def _get_imagename():
    tagstr = "-%s" % p.Tag if p.Tag else ""
    return rhel_build() + "-wala-" + wala_build() + tagstr


def Install():
    get_newest_local_isoname()
    qcow2_path = p.TmpDir + _get_imagename() + ".qcow2"
    iso_path = p.isoDir + p.isoName + ".iso"
    newiso_path = p.TmpDir + p.isoName + "-ks.iso"
    return mk_iso(iso_path, newiso_path) or \
           mk_qcow2(newiso_path, qcow2_path)


def Convert():
    get_newest_local_isoname()
#    image_path = rhel_build() + "-wala-" + wala_build()
#    qcow2_path = p.TmpDir + image_path + ".qcow2"
#    vhd_path = p.vhdDir + image_path + ".vhd"
    image_name = _get_imagename()
    qcow2_path = p.TmpDir + image_name + ".qcow2"
    vhd_path = p.vhdDir + image_name + ".vhd"
    return qcow2_to_vhd(qcow2_path, vhd_path)


#def Setup():
#    os.chdir(os.path.split(os.path.realpath(__file__))[0])
#    if not os.path.isdir(p.MainDir):
#        os.makedirs(p.MainDir)
#    Run("/usr/bin/cp -r -f {0}/tools {1}".format(p.realpath, p.MainDir))
#    Run("/usr/bin/cp -r -f {0}/ks {1}".format(p.realpath, p.MainDir))
#    Log("Setup finished.")
#    return 0


###### Main ######

def main():
    if len(sys.argv) == 1:
        sys.exit(Usage())
    #    LoggerInit("/var/log/azure_image_prepare.log")
    LoggerInit("/tmp/azure_image_prepare.log")

    # Check if this script runs on RHEL-6 or RHEL-7
#    CheckPlatform()

    # Set global parameters
    realpath = os.path.split(os.path.realpath(__file__))[0]
    configfile_path = "%s/azure_image_prepare.yaml" % realpath
    global p
    p = Params(configfile_path, realpath)

    # Check file lists
    dir_create_list = [p.TmpDir, p.vhdDir, p.isoDir]
    file_exist_list = [p.srcksPath, p.toolsDir, p.patchDir, p.rhuiDir]

#    ret = Setup()
#    ret += CheckEnvironment(dir_create_list, file_exist_list)
#    if ret != 0:
#        ErrorAndExit("Environment Check is not pass")
    # argv
    for a in sys.argv[1:]:
        if re.match("^([-/]*)(help|usage|\?)", a):
            sys.exit(Usage())
#        elif re.match("^([-/]*)setup", a):
#            sys.exit(Setup())
        elif re.match("^([-/]*)check", a):
            sys.exit(CheckEnvironment(dir_create_list, file_exist_list))
        elif re.match("^([-/]*)all", a):
            if CheckEnvironment(dir_create_list, file_exist_list) == 1:
                ErrorAndExit("Environment Check is not pass")
            sys.exit(Download() or Install() or Convert())
        elif re.match("^([-/]*)downloadwala", a):
#            sys.exit(download_wala(p.WalaVersion))
            sys.exit(Download_wala())
        elif re.match("^([-/]*)download", a):
            sys.exit(Download())
        elif re.match("^([-/]*)install", a):
            sys.exit(Install())
        elif re.match("^([-/]*)convert", a):
            sys.exit(Convert())
        elif re.match("^([-/]*)rhelbuild", a):
            print rhel_build()
            sys.exit(0)
        elif re.match("^([-/]*)walabuild", a):
            print wala_build()
            sys.exit(0)
        elif re.match("^([-/]*)localbuild", a):
            get_newest_local_isoname()
            if p.isoName:
                print re.findall(re.compile('RHEL-\d\.\d-\d{8}.\d'), p.isoName)[0]
            else:
                print ''
            sys.exit(0)
        else:
            print "Wrong parameters."
            sys.exit(Usage())


if __name__ == '__main__':
    main()
