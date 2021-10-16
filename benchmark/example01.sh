#!/bin/bash

MOUNTDIR="/tmp/example01";
ISO_MOUNTDIR="/tmp/isofile";
USER="ph0llux";
PWD=$(pwd);

#create the example image and mount it.
dd if=/dev/zero of=example01.dd count=10485760 bs=2048 status=progress;
mkfs.ext4 example01.dd;
mkdir $MOUNTDIR;
sudo mount example01.dd $MOUNTDIR;
sudo chown $USER -R $MOUNTDIR;


mkdir -p $ISO_MOUNTDIR


# download and extract example data.
wget https://cdimage.debian.org/debian-cd/current/amd64/iso-dvd/debian-11.1.0-amd64-DVD-1.iso -O $MOUNTDIR/isofile.iso
sudo mount -o loop $MOUNTDIR/isofile.iso $ISO_MOUNTDIR
cp -rv $ISO_MOUNTDIR/* $MOUNTDIR

sudo umount $ISO_MOUNTDIR
sudo umount $MOUNTDIR