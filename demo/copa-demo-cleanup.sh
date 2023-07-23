#!/bin/bash

########################
# include the magic
########################
. demo-magic.sh

# hide the evidence
clear

# Put your stuff here
pei "docker kill buildkitd"
pei "docker rmi nginx:1.18.0-patched --force"
pei "docker rmi nginx:1.18.0 --force"
pei "rm nginx.1.18.0.json"
