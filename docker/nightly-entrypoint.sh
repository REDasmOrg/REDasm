#!/bin/bash

git clone --branch=master https://github.com/REDasmOrg/REDasm.git /redasm
# git checkout -qf $VERSION
pushd redasm
git submodule update --init --recursive
mkdir -p build
pushd build
qmake CONFIG+=release ..
make
cp REDasm /deploy
popd
