#!/usr/bin/python
"""
Library used to provide the appropriate data dir for Azure test.

:copyright: 2016 Red Hat Inc.
"""
import inspect
import os
import sys
import glob
import shutil
import stat

from avocado.core import data_dir

# we're running from source code directories
azuretest_init = sys.modules['azuretest'].__file__
azuretest_dir = os.path.realpath(os.path.dirname(azuretest_init))
_ROOT_PATH = os.path.dirname(azuretest_dir)

ROOT_DIR = os.path.abspath(_ROOT_PATH)
DATA_DIR = os.path.join(data_dir.get_data_dir(), 'avocado-azure')
SHARED_DIR = os.path.join(ROOT_DIR, 'shared')
BASE_DOWNLOAD_DIR = os.path.join(SHARED_DIR, 'downloads')
DOWNLOAD_DIR = os.path.join(DATA_DIR, 'downloads')
TEST_PROVIDERS_DIR = os.path.join(ROOT_DIR, 'test-providers.d')
BACKING_DATA_DIR = None


class SubdirList(list):

    """
    List of all non-hidden subdirectories beneath basedir
    """

    def __in_filter__(self, item):
        if self.filterlist:
            for _filter in self.filterlist:
                if item.count(str(_filter)):
                    return True
            return False
        else:
            return False

    def __set_initset__(self):
        for dirpath, dirnames, filenames in os.walk(self.basedir):
            del filenames  # not used
            # Don't modify list while in use
            del_list = []
            for _dirname in dirnames:
                if _dirname.startswith('.') or self.__in_filter__(_dirname):
                    # Don't descend into filtered or hidden directories
                    del_list.append(_dirname)
                else:
                    self.initset.add(os.path.join(dirpath, _dirname))
            # Remove items in del_list from dirnames list
            for _dirname in del_list:
                del dirnames[dirnames.index(_dirname)]

    def __init__(self, basedir, filterlist=None):
        self.basedir = os.path.abspath(str(basedir))
        self.initset = set([self.basedir])  # enforce unique items
        self.filterlist = filterlist
        self.__set_initset__()
        super(SubdirList, self).__init__(self.initset)


class SubdirGlobList(SubdirList):

    """
    List of all files matching glob in all non-hidden basedir subdirectories
    """

    def __initset_to_globset__(self):
        globset = set()
        for dirname in self.initset:  # dirname is absolute
            pathname = os.path.join(dirname, self.globstr)
            for filepath in glob.glob(pathname):
                if not self.__in_filter__(filepath):
                    globset.add(filepath)
        self.initset = globset

    def __set_initset__(self):
        super(SubdirGlobList, self).__set_initset__()
        self.__initset_to_globset__()

    def __init__(self, basedir, globstr, filterlist=None):
        self.globstr = str(globstr)
        super(SubdirGlobList, self).__init__(basedir, filterlist)


def get_backing_data_dir():
    return DATA_DIR


BACKING_DATA_DIR = get_backing_data_dir()


def get_root_dir():
    return ROOT_DIR


def get_data_dir():
    return DATA_DIR


def get_shared_dir():
    return SHARED_DIR


def get_tmp_dir(public=True):
    """
    Get the most appropriate tmp dir location.

    :param public: If public for all users' access
    """
    tmp_dir = data_dir.get_tmp_dir()
    if public:
        tmp_dir_st = os.stat(tmp_dir)
        os.chmod(tmp_dir, tmp_dir_st.st_mode | stat.S_IXUSR |
                 stat.S_IXGRP | stat.S_IXOTH | stat.S_IRGRP | stat.S_IROTH)
    return tmp_dir


def get_download_dir():
    if not os.path.isdir(DOWNLOAD_DIR):
        shutil.copytree(BASE_DOWNLOAD_DIR, DOWNLOAD_DIR)
    return DOWNLOAD_DIR


TEST_PROVIDERS_DOWNLOAD_DIR = os.path.join(get_data_dir(), 'test-providers.d',
                                           'downloads')


def get_base_test_providers_dir():
    return TEST_PROVIDERS_DIR


def get_test_providers_dir():
    """
    Return the base test providers dir (at the moment, test-providers.d).
    """
    return os.path.dirname(TEST_PROVIDERS_DOWNLOAD_DIR)


def get_test_provider_dir(provider):
    """
    Return a specific test providers dir, inside the base dir.
    """
    return os.path.join(TEST_PROVIDERS_DOWNLOAD_DIR, provider)


def clean_tmp_files():
    tmp_dir = get_tmp_dir()
    if os.path.isdir(tmp_dir):
        hidden_paths = glob.glob(os.path.join(tmp_dir, ".??*"))
        paths = glob.glob(os.path.join(tmp_dir, "*"))
        for path in paths + hidden_paths:
            shutil.rmtree(path, ignore_errors=True)


if __name__ == '__main__':
    print "root dir:         " + ROOT_DIR
    print "tmp dir:          " + get_tmp_dir()
    print "data dir:         " + DATA_DIR
    print "test providers dir: " + TEST_PROVIDERS_DIR
