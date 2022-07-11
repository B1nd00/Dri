#!/bin/bash
set -x

node_num=`sudo dmesg -t | grep AXIADO_TPM2_COMPAT | grep mknod | awk '{ print $6 }'`
sudo mknod /dev/tpm2_compat c ${node_num} 0
sudo chmod o+w /dev/tpm2_compat
