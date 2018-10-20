#!/bin/bash

build_dir=${PWD}/release

image=redasm-nightly
nightly=redasm_nightly

imageService() {
    docker build -t ${image} .
}

nightlyService() {
    mkdir -p ${build_dir}
    docker run --rm -v ${build_dir}:/deploy --name ${nightly} ${image} .
}

rmService() {
    docker rmi ${image}
}

case "$1" in
    image)   imageService ;;
    nightly)    nightlyService ;;
    rm)    rmService ;;
    *) echo "usage: $0"
       echo "  image:   builds docker image"
       echo "  stable:  currently not implemented"
       echo "  nightly: runs a container to build a redasm as nightly version"
       echo "  rm:      removes docker image"
       exit 1
       ;;
esac
