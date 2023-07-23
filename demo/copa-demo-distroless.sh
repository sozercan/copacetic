#!/bin/bash

########################
# include the magic
########################
. demo-magic.sh

# hide the evidence
clear

# Put your stuff here

p "Pulling opa:0.46.0 (based on distroless/base) container image from DockerHub"
pei "docker pull docker.io/openpolicyagent/opa:0.46.0"

p "Use Trivy to output the vulnerabilities in the docker.io/openpolicyagent/opa:0.46.0 container image"
pei "trivy image --vuln-type os --ignore-unfixed docker.io/openpolicyagent/opa:0.46.0"

p "Use Trivy to scan the opa:0.46.0 container image saving the output to opa.0.46.0.json"
pei "trivy image --vuln-type os --ignore-unfixed -f json -o opa.0.46.0.json docker.io/openpolicyagent/opa:0.46.0"

p "Run buildkit in a container locally, we'll need it to run copa"
pei "docker run --detach --rm --privileged -p 127.0.0.1:8888:8888/tcp --name buildkitd --entrypoint buildkitd moby/buildkit:v0.11.6 --addr tcp://0.0.0.0:8888"

p "Confirm the buildkit container is running"
pei "docker ps"

p "Use copa to patch the docker.io/openpolicyagent/opa:0.46.0 container image outputting the patched container image to docker.io/openpolicyagent/opa:0.46.0-patched"
pei "copa patch -i docker.io/openpolicyagent/opa:0.46.0 -r opa.0.46.0.json -t 0.46.0-patched -a tcp://0.0.0.0:8888"

p "Check that the docker.io/openpolicyagent/opa:0.46.0-patched container image is present locally"
pei "docker images | grep 0.46.0"

p "Use Trivy to scan the docker.io/openpolicyagent/opa:0.46.0-patched container image"
pei "trivy image --vuln-type os --ignore-unfixed docker.io/openpolicyagent/opa:0.46.0-patched"

p "Verify that the patched container image runs"
pei "docker run docker.io/openpolicyagent/opa:0.46.0-patched"

p "Learn more about Copa at - https://github.com/project-copacetic/copacetic"


