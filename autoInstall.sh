#!/bin/bash

# Just a simple script to install my theme setup for future distros I try
# all credit goes to the original theme/plugin creators that I'll list down below and in the README.

# shell & theme 
# https://ohmyz.sh 
# https://github.com/reobin/typewritten

# terminal
# https://github.com/kovidgoyal/kitty
# Color theme - Dracula
# Font - JetBrains Mono

# Icons
# https://github.com/polybar/polybar

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

echo "running update...."
# apt-get update 

if ! command -v curl &> /dev/null; then
    echo "installing curl"
    apt install curl -y
fi 

# next install zsh 




