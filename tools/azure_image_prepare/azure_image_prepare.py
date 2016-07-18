#!/usr/bin/python2.7
import os,sys,urllib2,time,re,shutil
import platform
import subprocess
import string
import hashlib
import base64
import pwd

AzureImagePrepareConf = """\
#
# Azure Image Prepare Script Configuration
#

Project=6.8                                 # Specify the project.
Version=None                                # Specify a RHEL version you need. If set, the Project will be ignored. (e.g.)Version=RHEL-6.8-20160413.0
WalaVersion=None                            # Specify a WALinuxAgent rpm name. (e.g.)WalaVersion=WALinuxAgent-2.0.16-1.el6.noarch.rpm
Baseurl=http://download.eng.pek2.redhat.com/rel-eng/  # The URL to download original iso. Must be end with "/".
MainDir=/home/autotest/                     # The main folder to store original iso. Must be end with "/".
TmpDir=/home/tmp/azure/                     # Temporary folder to store the ks floppy, new iso and mount point. Must be end with "/".
Logfile=/var/log/azure_image_prepare.log    # Logfile
Verbose=n                                   # Enable verbose logs
ImageSize=8                                 # The VM image disk size in GB
"""

class ConfigurationProvider(object):
    """
    Parse and store key:values in azure_image_prepare.conf
    """
    def __init__(self, configfile_path):
        self.values = dict()
        if configfile_path is None:
            configfile_path = "%s/azure_image_prepare.conf" % p.realpath
        if not os.path.isfile(configfile_path):
            Warn("Missing configuration in {0}".format(configfile_path))
            self.setconf(configfile_path)
        try:
            for line in GetFileContents(configfile_path).split('\n'):
                if not line.startswith("#") and "=" in line:
                    parts = line.split()[0].split('=')
                    value = parts[1].strip("\" ")
                    if value != "None":
                        self.values[parts[0]] = value
                    else:
                        self.values[parts[0]] = None
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
        return self.values.get(key)


class Params(object):
    """
    Global parameters class
    """
    def __init__(self, configfile_path, realpath):
        self.realpath = realpath
        c=ConfigurationProvider(configfile_path)
        self.Project=c.get("Project")
        self.Version=c.get("Version")
        if self.Version is not None:
            self.Project=self.Version.split('-')[1]
        self.WalaVersion=c.get("WalaVersion")
        self.TmpDir=c.get("TmpDir")
        self.MainDir=c.get("MainDir")
        self.Baseurl=c.get("Baseurl")
        get_verbose=c.get("Verbose")
        self.Logfile=c.get("Logfile")
        self.ImageSize=int(c.get("ImageSize"))
        if get_verbose is not None and get_verbose.lower().startswith("y"):
            myLogger.verbose = True
       # self.ConfigDir=os.path.dirname(configfile_path)+"/"
        self.walaDir=self.MainDir+"wala/RHEL-"+self.Project[0]+"/"
        self.ksDir=self.MainDir+"ks/"
        self.toolsDir=self.MainDir+"tools/"
        self.vhdDir=self.MainDir+"vhd/"
        self.isoDir=self.MainDir+"iso/RHEL-"+self.Project+"/"
        self.newisoDir=self.TmpDir+"newiso/"
        self.srcksPath=self.ksDir+"RHEL-"+self.Project.split('.')[0]+".cfg"
        self.isoName=""
        self.walaName=""


class Logger(object):

    def __init__(self, filepath, verbose=False):
        """
        Construct an instance of Logger.
        """
        self.verbose=verbose
        self.filepath=filepath

    def Log(self,message):
        """
        Write 'message' to logfile.
        """
        timestr=time.strftime('[%Y-%m-%d %H:%M:%S] ')
        if self.filepath:
            try:
                with open(self.filepath, "a") as F :
                    message = filter(lambda x : x in string.printable, message)
                    F.write(timestr+message.encode('ascii','ignore') + "\n")
            except IOError, e:
                print e
                pass

    def LogIfVerbose(self,message):
        if self.verbose:
            Log(message)
        else:
            pass

    def LogWithPrefix(self,prefix, message):
        """
        Prefix each line of 'message' with 'prefix'.
        """
        for line in message.split('\n'):
            line = prefix + line
            self.Log(line)

    def Warn(self,message):
        """
        Prepend the text "WARNING:" to the prefix for each line in 'message'.
        """
        self.LogWithPrefix("WARNING:", message)

    def Error(self, message):
        """
        Prepend the text "ERROR:" to the prefix for each line in 'message'.
        """
        self.LogWithPrefix("ERROR:", message)

def LoggerInit(logfile_path,verbose=False):
    """
    Create log object and export its methods to global scope.
    """
    global Log,LogWithPrefix,LogIfVerbose,Error,Warn,myLogger
    l=Logger(logfile_path,verbose)
    Log,LogWithPrefix,LogIfVerbose,Error,Warn,myLogger = l.Log,l.LogWithPrefix,l.LogIfVerbose,l.Error,l.Warn,l

def ErrorAndExit(message):
    """
    Error(msaage);sys.exit(1)
    """
    Error(message+". Exit.")
    sys.exit(1)

def GetFileContents(filepath,asbin=False):
    """
    Read and return contents of 'filepath'.
    """
    mode='r'
    if asbin:
        mode+='b'
    c=None
    try:
        with open(filepath, mode) as F:
            c=F.read()
    except IOError, e:
        Error('Reading from file ' + filepath + 'failed. Exception: ' + str(e))
        return None
    return c

def SetFileContents(filepath, contents):
    """
    Write 'contents' to 'filepath'.
    """
    if type(contents) == str :
        contents=contents.encode('latin-1', 'ignore')
    try:
        with open(filepath, "wb+") as F :
            F.write(contents)
    except (IOError,TypeError) as e:
        Error('Writing to file ' + filepath + ' failed. Exception: ' + str(e))
        return None
    return 0

def Run(cmd,chk_err=True):
    """
    Calls RunGetOutput on 'cmd', returning only the return code.
    If chk_err=True then errors will be reported in the log.
    If chk_err=False then errors will be suppressed from the log.
    """
    retcode,out=RunGetOutput(cmd,chk_err)
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
        output=subprocess.check_output(cmd,stderr=subprocess.STDOUT,shell=True)
    except subprocess.CalledProcessError,e :
        if chk_err and log_cmd:
            Error('CalledProcessError.  Error Code is ' + str(e.returncode)  )
            Error('CalledProcessError.  Command string was ' + e.cmd  )
            Error('CalledProcessError.  Command result was ' + (e.output[:-1]).decode('latin-1'))
        return e.returncode,e.output.decode('latin-1')
    return 0,output.decode('latin-1')

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
    if u != None:
        os.chown(filepath, u[2], u[3])

def CreateDir(dirpath, user=None, mode=0755):
    """
    Attempt os.makedirs, catch all exceptions.
    Call ChangeOwner afterwards.
    """
    if not user:
        user = RunGetOutput("whoami")[1].split('\n')
    LogIfVerbose("Try to create "+dirpath)
    if os.path.exists(dirpath):
        LogIfVerbose(dirpath+" already exists.")
        return True
    else:
        try:
            os.makedirs(dirpath, mode)
        except Exception, e:
            Error("Cannot make dir "+dirpath+". Exception: "+str(e))
            return False
        ChangeOwner(dirpath, user)
        LogIfVerbose("Create "+dirpath+" successfully.")
        return True

def CheckFileExist(filepath,ifexit=True):
    """
    Check if file exists. If not, save log and exit.
    """
    if os.path.isfile(filepath)==False:
        if ifexit:
            ErrorAndExit(filepath+" doesn't exist")
        else:
            Error(filepath+" doesn't exist.")
            return False
    return True

def CheckFileNotExist(filepath,ifexit=True):
    """
    If file exists, remove it.
    """
    if os.path.isfile(filepath):
        Warn(filepath+" already exists. Remove it.")
        try:
            os.remove(filepath)
        except Exception, e:
            if ifexit:
                ErrorAndExit("Cannot remove "+filepath+". Exception: "+str(e))
            else:
                Error("Cannot remove "+filepath+". Exception: "+str(e))
                return False
    return True

def _hashfile(afile, hasher, blocksize=65536):
    buf = afile.read(blocksize)
    while len(buf) > 0:
        hasher.update(buf)
        buf = afile.read(blocksize)
    return hasher.hexdigest()

###### Download the latest build ######

def calculate_md5(afile):
    return _hashfile(open(afile, 'rb'), hashlib.md5())

def get_latest_build():
    """
    Make a dictionary to store project:version pairs.
    """
    LogIfVerbose("Getting RHEL build dictionary...")
    LogIfVerbose("Open "+p.Baseurl)
    try:
        alldata=urllib2.urlopen(p.Baseurl).read()
    except urllib2.HTTPError, e:
        ErrorAndExit("Cannot open "+p.Baseurl+". Exception: "+str(e))
    r=re.compile('RHEL-\d.\d-\d+.\d')
    tree_list=r.findall(alldata)
    tree_list=list(set(tree_list))
    tree_project_dict={}
    tree_version_dict={}
    for tree in tree_list:
        _,tree_project,tree_version=tree.split('-')
        tree_date,tree_subversion=tree_version.split('.')
        tree_project_dict.setdefault(tree_project,[]).append(tree_date)
        tree_version_dict.setdefault(tree_date,[]).append(tree_subversion)
    max_dict={}
    for tree_project in tree_project_dict.keys():
        max_date=max(list(tree_project_dict[tree_project]))
        max_version=max(list(tree_version_dict[max_date]))
        max_dict.setdefault(tree_project,[]).append('RHEL-'+tree_project+'-'+max_date+'.'+max_version)
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
        latest_build=get_latest_build()[p.Project][0]
    else:
        ErrorAndExit("There must be Version or Project parameter in the azure_image_prepare.conf")
    iso_name = latest_build+'-Server-x86_64-dvd1.iso'
    iso_url = p.Baseurl+latest_build+'/compose/Server/x86_64/iso/'+iso_name
    md5_url = iso_url+'.MD5SUM'
    iso_folder = p.MainDir+'iso/RHEL-'+p.Project+'/'
    iso_fullpath = iso_folder+iso_name
    CreateDir(iso_folder)
#    if os.path.exists(iso_folder)==False:
#        os.makedirs(iso_folder)
    try:
        md5url=urllib2.urlopen(md5_url)
    except urllib2.HTTPError, e:
        ErrorAndExit("Cannot open "+md5_url+". Exception: "+str(e))
    if float(p.Project) < 7.0:
        md5 = md5url.read().split(' ')[-1].strip('\n')
    else:
        md5 = md5url.read().split(' ')[0]
    while True:
        if os.path.isfile(iso_fullpath)==False:
            outf=open(iso_fullpath,'wb')
            try:
                f=urllib2.urlopen(iso_url)
            except urllib2.HTTPError, e:
                ErrorAndExit("Cannot open "+iso_url+". Exception: "+str(e))
#            f=urllib2.urlopen(md5_url)
            c=0
            Log("Download "+iso_fullpath+" begin.")
            while True:
                s=f.read(1024*1024*10)
                if len(s)==0:
                    break
                outf.write(s)
                c+=len(s)
                LogIfVerbose("Downloading "+str(c))
            Log("Download "+iso_fullpath+" finished.")
        else:
            Warn(iso_fullpath+" already exists.")
        time.sleep(1)
        Log("Checking MD5...")
        realmd5=calculate_md5(iso_fullpath)
        LogIfVerbose("Target MD5: "+md5)
        LogIfVerbose("Real MD5:   "+realmd5)
        if realmd5 == md5:
#        if calculate_md5("/home/images/iso/RHEL-6.8-20160413.0-Server-x86_64-dvd1.iso") == md5:
            Log("MD5 matches. ISO is ready.")    
            break
        Error("MD5 does not match. Download again.")
        os.remove(iso_fullpath)
    return 0

def get_newest_local_isoname():
    """
    Return the newest version iso name in the p.isoDir.
    """
    version_dict={}
    filelist=os.listdir(p.isoDir)
    for filename in filelist:
        version=filename.split("-")[2]
        version_dict.setdefault(version.split('.')[0],[]).append(version.split('.')[1])
    max_date=max(list(version_dict.keys()))
    max_subversion=max(list(version_dict[max_date]))
    p.isoName="RHEL-"+p.Project+"-"+max_date+"."+max_subversion+"-Server-x86_64-dvd1"
    return 0

def get_latest_wala():
    """
    Get the latest wala build
    """
    if float(p.Project) < 7.0:
        brewcmd="brew latest-build extras-rhel-6 WALinuxAgent|grep WALinuxAgent|awk '{print $1}'"
    else:
        brewcmd="brew latest-build extras-rhel-"+str(p.Project)+" WALinuxAgent|grep WALinuxAgent|awk '{print $1}'"
    rcode, walabuild=RunGetOutput(brewcmd)
    if rcode != 0:
        ErrorAndExit("Cannot get the latest wala build")
#    For brewkoji-1.9-1
#    return walabuild.strip('\n')+".noarch.rpm"
    return walabuild.strip('\n')

def download_wala(version=None):
    """
    Download the latest wala package from brew.
    """
    if version != None:
#        For brewkoji-19-1
#        p.walaName = "WALinuxAgent-%s.el%s.noarch.rpm" % (version, str(p.Project).split('.')[0])
        p.walaName = "WALinuxAgent-%s.el%s" % (version, str(p.Project).split('.')[0])
    else:
        p.walaName=get_latest_wala()
    CreateDir(p.walaDir)
    for walafile in os.listdir(p.walaDir):
        if walafile.find(p.walaName+".noarch.rpm") != -1:
            Log("%s.noarch.rpm already exists." % p.walaName)
            return 0
    os.chdir(p.walaDir)
#    For brewkoji-19-1
#    Run("brew download-build --rpm "+p.walaName)
    Run("brew download-build --arch=noarch %s" % p.walaName)
    Log("Download "+p.walaDir+p.walaName+".noarch.rpm successfully.")
    return 0


###### Install ######

def mk_iso(iso_path,newiso_path):
    """
    Modify isolinux.cfg. Make new iso.
    """
    if (iso_path == None) or (os.path.isfile(iso_path)==False):
        ErrorAndExit("No RHEL iso. Please download again")
    iso_mount=p.TmpDir+'iso/'
    newiso_mount=p.TmpDir+'newiso/'
    isolinux=newiso_mount+'isolinux/isolinux.cfg'
    CreateDir(iso_mount)
    # Mount origional iso and copy to new path.
    retcode,out = RunGetOutput("mount -o loop " + iso_path + " " + iso_mount)
    if retcode == False and out.find("mounting read-only") == -1:
        ErrorAndExit("Cannot mount " + iso_path + " to "+iso_mount)
    Log("Copying iso to newiso...")
    try:
        shutil.copytree(iso_mount,newiso_mount)
    except Exception, e:
        ErrorAndExit("Copy iso tree fail. Exception: " + str(e))
    Log("Copy iso tree successfully.")
    Run("umount "+iso_mount)
    # Modify isolinux.cfg. Add ks=floppy.
    CheckFileExist(isolinux)
    if float(p.Project) < 7.0:
#        Run("sed -i '/^\ *append\ initrd/s/$/\ ks=floppy/' "+isolinux)
        Run("sed -i %s\
            -e 's/timeout 600/timeout 30/'\
            -e '/append initrd=/s/$/ ks=floppy/'" % isolinux)
    elif float(p.Project) >= 7.0:
#        Run("sed -i '/^\ *append\ initrd/s/$/\ ks=cdrom\:\/dev\/sr1\:\/ks.cfg/' "+isolinux)
        Run("sed -i %s\
            -e '/menu[[:space:]][[:space:]]*default/d'\
            -e 's/timeout 600/timeout 30/'\
            -e '/append initrd=/s/$/ ks=cdrom:\/dev\/fd0:\/ks.cfg/'\
            -e '/^label linux/{N;s/$/\\n  menu default/}'" % isolinux)
    os.chmod(isolinux, 444)
    # Make new iso
    isoinfo = RunGetOutput("isoinfo -d -i "+iso_path)[1]
    m = re.search("Volume id:([^\n]*)", isoinfo)
    volid = m.group(1)[1:]
#    Run("mkisofs -o "+newiso_path+" -b isolinux/isolinux.bin -c isolinux/boot.cat -no-emul-boot -boot-load-size 4 -boot-info-table -R -J -v -T "+newiso_mount)
    Run("mkisofs -J -R -v -T -V \""+volid+"\" -o "+newiso_path+" -b isolinux/isolinux.bin -c isolinux/boot.cat -no-emul-boot -boot-load-size 4 -boot-info-table "+newiso_mount)
    Log("Make "+newiso_path+" successfully.")
    return 0

def mk_floppy(srcks_path,floppy_path):
    """
    Make ksfloppy.img. Put ks.cfg,wala package and tools in it.
    """
    CheckFileNotExist(floppy_path)
    floppy_mount=p.TmpDir+"ksfloppy/"
    CreateDir(floppy_mount)
    #Create new floppy img
    Run("dd bs=512 count=2880 if=/dev/zero of="+floppy_path)
    Run("mkfs.msdos "+floppy_path)
    Run("mount -o loop "+floppy_path+" "+floppy_mount)
    #Copy ks file to floppy
    dstks_path=floppy_mount+"ks.cfg"
    CheckFileExist(srcks_path)
    try:
        shutil.copy(srcks_path,dstks_path)
    except Exception, e:
        ErrorAndExit("Cannot copy "+srcks_path+" to "+floppy_mount)
    #Copy WALinuxAgent package to floppy
    download_wala(p.WalaVersion)
    # For brewkoji-1.9-1
    # wala_fullname = p.walaName
    wala_fullname = p.walaName + ".noarch.rpm"
    try:
        shutil.copy(p.walaDir+wala_fullname, floppy_mount+wala_fullname)
    except Exception, e:
        ErrorAndExit("Cannot copy "+p.walaDir+wala_fullname+" to "+floppy_mount)
    #Copy tools(fio,iperf3) to floppy
    try:
        shutil.copytree(p.toolsDir,floppy_mount+"tools/")
    except Exception, e:
        ErrorAndExit("Cannot copy "+p.toolsDir+" to "+floppy_mount+". Exception: "+str(e))
    Run("umount "+floppy_mount)
    Log("Create ks floppy successfully.")
    return 0

def mk_qcow2(newiso_path,qcow2_path,floppy_path):
    """
    Install img through kickstart.
    """
    #Create empty qcow2 file
    Log("Install qcow2...")
    Run("qemu-img create %s %dG -f qcow2" % (qcow2_path, p.ImageSize))
    CheckFileExist(qcow2_path)
    #Install image
    Run("virt-install --name walatestimg --ram 1024 --network bridge=virbr0 --vcpus 1 --cdrom "+newiso_path+" --disk path="+qcow2_path+",bus=virtio --disk path="+floppy_path+",device=floppy --noreboot")
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
        ErrorAndExit(vhd_path+" file size is wrong. Target: %d Real: %d" % (target_size, vhd_size))
    Log("Make %s successfully." % vhd_path)
    return 0

def Usage():
    """
    Print the usage.
    """
    print("usage: " + sys.argv[0] + " [-check|-all|-download|-install|-convert|-help] [-verbose]")
    return 0

def _umount(mount_path):
    """
    Force umount mount_path
    """
    if os.path.exists(mount_path) and RunGetOutput("mount|grep "+mount_path, chk_err=False)[1] != "":
        Run("fuser -km "+mount_path, chk_err=False)
        time.sleep(0.5)
        Run("umount "+mount_path)

def CheckEnvironment(dir_create_list,exist_file_list):
    """
    Prepare the environment before running.
    """
    ret = 0
    Run("virsh destroy walatestimg", chk_err=False)
    Run("virsh undefine walatestimg", chk_err=False)
    _umount(p.TmpDir+"iso")
    _umount(p.TmpDir+"newiso")
    _umount(p.TmpDir+"ksfloppy")
    if os.path.isdir(p.TmpDir):
        try:
            shutil.rmtree(p.TmpDir)
        except Exception, e:
            Error("Cannot remove "+p.TmpDir+". Error code: "+str(e))
            ret = 1
    Run("rm -rf "+p.TmpDir)
    for dirname in dir_create_list:
        if not CreateDir(dirname):
            ret = 1
    for filename in exist_file_list:
        if not CheckFileExist(filename,False):
            ret = 1
    if ret == 0:
        Log("Environment Check result is True")
    else:
        Log("Environment Check result is False")
    return ret

def Download():
    return download_iso(p.Version)

def Install():
    get_newest_local_isoname()
    floppy_path=p.TmpDir+"ksfloppy.img"
    qcow2_path=p.TmpDir+p.isoName+".qcow2"
    iso_path=p.isoDir+p.isoName+".iso"
    newiso_path=p.TmpDir+p.isoName+"-ks.iso"
    srcks_path=p.srcksPath
    return mk_iso(iso_path,newiso_path) or \
           mk_floppy(srcks_path,floppy_path) or \
           mk_qcow2(newiso_path,qcow2_path,floppy_path)

def Convert():
    get_newest_local_isoname()
    vhd_path=p.vhdDir+p.isoName+".vhd"
    qcow2_path=p.TmpDir+p.isoName+".qcow2"
    return qcow2_to_vhd(qcow2_path, vhd_path)

def Setup():
    os.chdir(os.path.split(os.path.realpath(__file__))[0])
    if not os.path.isdir(p.MainDir):
        os.makedirs(p.MainDir)
    Run("cp -r tools %s" % p.MainDir)
    Run("cp -r ks %s" % p.MainDir)
    Log("Setup finished.")
    return 0

###### Main ######

def main():
    if len(sys.argv) == 1:
        sys.exit(Usage())
#    LoggerInit("/var/log/azure_image_prepare.log")
    LoggerInit("/tmp/azure_image_prepare.log")

    # Check if this script runs on RHEL-6 or RHEL-7
    CheckPlatform()

    # Set global parameters
    realpath = os.path.split(os.path.realpath(__file__))[0]
    configfile_path = "%s/azure_image_prepare.conf" % realpath
    global p
    p=Params(configfile_path, realpath)

    # Check file lists
    dir_create_list=[p.TmpDir,p.MainDir,p.ksDir,p.vhdDir,p.isoDir]
    file_exist_list=[p.srcksPath]

    # argv
    ret = 0
    for a in sys.argv[1:]:
        if re.match("^([-/]*)(help|usage|\?)", a):
            sys.exit(Usage())
        elif re.match("^([-/]*)verbose", a):
            myLogger.verbose = True
        elif re.match("^([-/]*)setup", a):
            sys.exit(Setup())
        elif re.match("^([-/]*)check", a):
            sys.exit(CheckEnvironment(dir_create_list,file_exist_list))
        elif re.match("^([-/]*)all", a):
            if CheckEnvironment(dir_create_list,file_exist_list) == 1:
                ErrorAndExit("Environment Check is not pass")
            sys.exit(Download() or Install() or Convert())
        elif re.match("^([-/]*)download", a):
            sys.exit(Download())
        elif re.match("^([-/]*)install", a):
            sys.exit(Install())
        elif re.match("^([-/]*)convert", a):
            sys.exit(Convert())
        elif re.match("^([-/]*)rhelbuild", a):
#            get_latest_build()
            if p.Version is not None:
                rhel_build = p.Version
            else:
                rhel_build = get_latest_build()[p.Project][0]
            print rhel_build
            sys.exit(0)
        elif re.match("^([-/]*)walabuild", a):
            # For brewkoji-1.9-1
            # wala_build = get_latest_wala().split('.el')[0].lstrip('WALinuxAgent-')
            if p.WalaVersion is not None:
                wala_build = p.WalaVersion
            else:
                wala_build = get_latest_wala().replace('WALinuxAgent-', '')
            Log("WALA version: %s" % wala_build)
            print wala_build
            sys.exit(0)
        else:
            print "Wrong parameters."
            sys.exit(Usage())


if __name__ == '__main__':
    main()
