%define name WALinuxAgent
%define version upstream_version
%define unmangled_version upstream_version
%define release 0

%if 0%{?rhel} < 7
%global initsys sysV
%else
%global initsys systemd
%endif

Summary: UNKNOWN
Name: %{name}
Version: %{version}
Release: %{release}%{?dist}
Source0: WALinuxAgent-upstream_version.tar.gz
Patch0002: 0002-Disable-autoupdate.patch
Patch0003: 0003-No-auto-update-when-upgrading.patch
Patch0004: 0004-Revert-Enable-autoupdate.patch
Patch0005: 0005-Revert-No-auto-update-when-upgrading.patch

License: Apache License Version 2.0
Group: Development/Libraries
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
Prefix: %{_prefix}
BuildArch: noarch
# Vendor: Yue Zhang, Stephen Zarkos, Eric Gable <walinuxagent@microsoft.com>
Url: https://github.com/Azure/WALinuxAgent

# rhel requirements

BuildRequires:  python2-devel
BuildRequires:  python-setuptools

Requires: util-linux
Requires: net-tools
Requires: openssh
Requires: openssh-server
Requires: openssl
Requires: parted
Requires: python-pyasn1

%if %{initsys} == systemd
Requires:       NetworkManager
%else
%if %{initsys} == sysV
Conflicts:      NetworkManager
%endif
%endif

%if %{initsys} == systemd
BuildRequires:   systemd
Requires(pre):  systemd
Requires(post):  systemd
Requires(preun): systemd
Requires(postun): systemd
%else
%if %{initsys} == sysv
Requires(post):  chkconfig
Requires(preun): chkconfig
Requires(preun): initscripts
Requires(postun): initscripts
%endif
%endif

%description
The Azure Linux Agent supports the provisioning and running of Linux
VMs in the Azure cloud. This package should be installed on Linux disk
images that are built to run in the Azure environment.


%prep
%setup -n %{name}-%{unmangled_version} -n %{name}-%{unmangled_version}

%patch0002 -p1
%patch0003 -p1
%patch0004 -p1
%patch0005 -p1

%build
python setup.py build

%install
python setup.py install --single-version-externally-managed -O1 --root=$RPM_BUILD_ROOT --record=INSTALLED_FILES

%clean
rm -rf $RPM_BUILD_ROOT

%post
%if %{initsys} == systemd
%systemd_post waagent.service
%else
%if %{initsys} == sysV
/sbin/chkconfig --add waagent
%endif
%endif

%preun
%if %{initsys} == systemd
%systemd_preun waagent.service
%else
%if %{initsys} == sysV
if [ $1 = 0 ]; then
        /sbin/service waagent stop >/dev/null 2>&1
        /sbin/chkconfig --del waagent
fi
%endif
%endif

%postun
%if %{initsys} == systemd
%systemd_postun_with_restart waagent.service
%else
%if %{initsys} == sysV
if [ "$1" -ge "1" ]; then
        /sbin/service waagent restart >/dev/null 2>&1 || :
fi
%endif
%endif

%files -f INSTALLED_FILES
%{python_sitelib}/*
%config(noreplace) %{_sysconfdir}/waagent.conf
%defattr(-,root,root)

%changelog
* Fri Apr 07 2017 Vitaly Kuznetsov <vkuznets@redhat.com> -  2.2.0-1.1.el7
- Enable AutoUpdate [bz#1434933]

* Mon Jan 16 2017 Miroslav Rezanina <mrezanin@redhat.com> - 2.2.0-4.el7
- agent-RHEL-7-hostname-533.patch [bz#1413674]
- agent-fix-for-hostnamectl-534.patch [bz#1413674]
- Resolves: bz#1413674
  ([WALA] Fail to send hostname to DHCP server during provisioning)

* Fri Sep 30 2016 Dave Anderson <anderson@redhat.com> - 2.2.0-1
- Update to v2.2.0
  Resolves: rhbz#1360492

* Wed Sep 21 2016 Dave Anderson <anderson@redhat.com> - 2.1.5-2
- Several QE updates to this file
  Resolves: rhbz#1360492

* Tue Sep 13 2016 Dave Anderson <anderson@redhat.com> - 2.1.5-1
- Update to v2.1.5
  Resolves: rhbz#1360492

* Thu Jan 14 2016 Dave Anderson <anderson@redhat.com> - 2.0.16-1
- Update to 2.0.16
  Resolves: rhbz#1296360

* Mon Jun 01 2015 Dave Anderson <anderson@redhat.com> - 2.0.13-1
- Update to upstream 2.0.13 package.
- Remove global commit md5sum and fix Source0 to point to correct location.
- Fix setup to deal with "WALinuxAgent-WALinuxAgent" naming scheme
- Added files reference for /udev/rules.d/99-azure-product-uuid.rules

* Thu May 07 2015 Dave Anderson <anderson@redhat.com> - 2.0.11-3
- Remove Requires: ntfsprogs for RHEL7

* Sat Jan 10 2015 Scott K Logan <logans@cottsay.net> - 2.0.11-2
- Use systemd for rhel7
- Own logrotate.d
- Fix python2-devel dep

* Sat Dec 20 2014 Scott K Logan <logans@cottsay.net> - 2.0.11-1
- Initial package
