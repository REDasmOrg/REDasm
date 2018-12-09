#! /bin/sh

OS_NAME=`uname`
ARCH=`uname -m`
BUILD_DATE=`date +%d%m%Y`
BUILD_ID="REDasm_"$OS_NAME"_"$ARCH"_"$BUILD_DATE
BUILD_ORG="REDasmOrg"
BUILD_REPO="REDasm-Builds"

zip -r ../$BUILD_ID.zip * # Generate archive
cd ..

# Prepare deploy
rm -rf $BUILD_REPO
git clone -b nightly https://${GITHUB_TOKEN}@github.com/$BUILD_ORG/$BUILD_REPO.git > /dev/null 2>&1
cd $BUILD_REPO
rm -rf *$OS_NAME*

if [ -f ../$BUILD_ID.zip ]; then
    mv ../$BUILD_ID.zip .
    git config user.email "buildbot@none.io"
    git config user.name "Travis Build Bot"
    git add -A .
    git commit -m "Updated Linux Nightly $BUILD_DATE"
    git push --quiet origin nightly > /dev/null 2>&1 
fi
