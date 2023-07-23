#!/bin/bash

########################
# include the magic
########################
. demo-magic.sh

# hide the evidence
clear

# Put your stuff here

p "Pulling nginx:1.18.0 container image from DockerHub"
pei "docker pull nginx:1.18.0"

p "Use Trivy to scan the nginx:1.18.0 container image saving the output to nginx.1.18.0.json"
pei "trivy image --vuln-type os --ignore-unfixed -f json -o nginx.1.18.0.json nginx:1.18.0"

p "Use Trivy to output the number of vulnerabilities in the nginx:1.18.0 container image"
pei "trivy image --vuln-type os --ignore-unfixed nginx:1.18.0 | grep Total"

p "Use Trivy to output the dpkg vulnerabilities in the nginx:1.18.0 container image"
pei "trivy image --vuln-type os --ignore-unfixed nginx:1.18.0 | grep dpkg"

p "Verify the dpkg version in the nginx:1.18.0 container image"
pei "docker run nginx:1.18.0 dpkg --version"

p "Run buildkit in a container locally, we'll need it to run copa"
pei "docker run --detach --rm --privileged -p 127.0.0.1:8888:8888/tcp --name buildkitd --entrypoint buildkitd moby/buildkit:v0.11.6 --addr tcp://0.0.0.0:8888"

p "Confirm the buildkit container is running"
pei "docker ps"

p "Use copa to patch the nginx:1.18.0 container image outputting the patched container image to nginx:1.18.0-patched"
pei "copa patch -i docker.io/library/nginx:1.18.0 -r nginx.1.18.0.json -t 1.18.0-patched -a tcp://0.0.0.0:8888"

p "Check that the nginx:1.18.0-patched container image is present locally"
pei "docker images | grep 1.18.0"

p "Use Trivy to scan the nginx:1.18.0-patched container image"
pei "trivy image --vuln-type os --ignore-unfixed nginx:1.18.0-patched | grep Total"

p "Verify that the patched container image runs"
pei "docker run nginx:1.18.0-patched"

p "Verify the dpkg version in the patched container image"
pei "docker run nginx:1.18.0-patched dpkg --version"

p "Learn more about Copa at - https://github.com/project-copacetic/copacetic"


