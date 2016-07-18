#!/bin/bash
tar -zxvf fio-2.1.10.tar.gz
cd fio-2.1.10
./configure
make
make install
