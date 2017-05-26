# avocado-azure
Avocado Azure is an avocado plugin that lets you run avocado tests on Microsoft Azure Virtual Machine instances.
v1.1: for WALinuxAgent-2.0.16-1

Must tools on host:
python2.6+
avocado
avocado-vt
azure-xplat-cli v1.10.0
brewkoji-1.13.1
nodejs0.10+
wget
virtualization packages(python-virtinst libvirt bridge-utils virt-manager qemu-kvm-tools virt-viewer virt-v2v virt-install qemu-img)
tcping
rpm-build

Must tools on guest:
nmap
tcpdump
fio
iperf3
# Installation
1. Install git, wget, nmap, tcpdump, tcping

    1). vi /etc/yum.repos.d/rhel7.repo

        [rhel7]
        name=rhel7
        baseurl=[RHEL-7 repo]
        enabled=1
        gpgcheck=0

    2). yum -y install git wget nmap tcpdump

    3). Install tcping:

        i). wget http://ftp.nluug.nl/os/Linux/distr/archlinux/community/os/x86_64/tcping-1.3.5-4-x86_64.pkg.tar.xz

        ii). xz -d tcping-1.3.5-4-x86_64.pkg.tar.xz

        iii). tar -xvf tcping-1.3.5-4-x86_64.pkg.tar

        iv). mv usr/bin/tcping /usr/bin/



2. Install virtualization packages:

    yum -y install kvm python-virtinst libvirt  bridge-utils virt-manager qemu-kvm-tools  virt-viewer  virt-v2v virt-install qemu-img

    systemctl start libvirtd

    systemctl enable libvirtd



3. Install brew:

    1). vi /etc/yum.repos.d/rhpkg.repo

        [rhpkg]
        name=rhpkg for Red Hat Enterprise Linux $releasever
        baseurl=[brewkoji repo]
        enabled=1
        gpgcheck=0

    2). yum -y install brewkoji



4. Install azure-cli:

    1). install nodejs, nmap: (Install nodejs 0.10. Current version: nodejs-0.10.46-1nodesource.el7.centos.x86_64)

        i). curl --silent --location https://rpm.nodesource.com/setup | bash -

        ii). yum -y install nodejs

    2). install azure-cli:

        npm install -g azure-cli

    * If want to install spefic azure-cli version:

        i). Uninstall previously version:

            npm uninstall azure-cli –g

        ii). Download specific version souce code:

            wget https://github.com/Azure/azure-xplat-cli/archive/<branch-name>.zip

            (e.g.) wget https://github.com/Azure/azure-xplat-cli/archive/v0.10.0-May2016.zip

        iii). unzip v0.10.0-May2016.zip

        iv). npm install -g <path to the azure cli unzip folder>



4. Install Avocado:

    1). pre-install packages:

        yum install -y git gcc python-devel python-pip libvirt-devel libyaml-devel redhat-rpm-config xz-devel

        * For RHEL7 there's no python-pip and libyaml-devel packages in repo:

        wget https://bootstrap.pypa.io/get-pip.py

        python get-pip.py        



    2). Download souce code from github

        avocado: git clone git://github.com/avocado-framework/avocado.git

        avocado-vt: git clone git://github.com/avocado-framework/avocado-vt.git



    3). Install avocado and avocado-vt:

        cd avocado

        pip install -r requirements.txt --upgrade  

        python setup.py develop

        cd avocado-vt

        pip install -r requirements.txt --upgrade  

        python setup.py develop

        * For RHEL-7: 

            i). pip install pexpect

            ii). wget ftp://195.220.108.108/linux/epel/7/x86_64/p/p7zip-15.09-9.el7.x86_64.rpm

                rpm -ivh p7zip-15.09-9.el7.x86_64.rpm



    4). Check:

        avocado vt-bootstrap --vt-type qemu

        If miss some packages, we need to install them ourselves. 



    5). Configuration:

        i). mv <avocado path>/etc/avocado /etc/

        ii). vi /etc/avocado/avocado.conf

            

5. Disable firewall and selinux:

    1). disable firewall:   

        systemctl stop firewalld

        systemctl disable firewalld

    2). close selinux:

        setenforce 0


# Usage
1. Fill in comfig.yaml with your accounts.

2. Edit the cases list in cfg/cases.yaml.

3. Run "python run_for_ci.py"

4. "new_rhel_detect.py" is used to detect the latest RHEL build and run avocado-azure automatically. You can add this script into crontab.
