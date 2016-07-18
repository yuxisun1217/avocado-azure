#!/bin/bash
tar -zxvf iperf-3.1.2-source.tar.gz
cd iperf-3.1.2
./configure
make
make install
