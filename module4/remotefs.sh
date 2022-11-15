#!/bin/bash
export USER=student
export HOST=isl-desktop3.inf.ethz.ch
export PORT=2100

sudo mkdir /mnt/islremotefs
sudo sshfs -o allow_other,IdentityFile=~/.ssh/isl_id_ed25519 -p $PORT $USER@$HOST:/home/student/ /mnt/islremotefs/