#! /bin/sh

DEPLOY_DIR=deploy
OS_NAME=`uname`
ARCH=`uname -m`
BUILD_DATE=`date +%d%m%Y`
BUILD_ID="REDasm_"$OS_NAME"_"$ARCH"_"$BUILD_DATE
BUILD_ORG="REDasmOrg"
BUILD_REPO="REDasm-Builds"

mkdir $DEPLOY_DIR
cp REDasm $DEPLOY_DIR  # Copy executable
cp -r database $DEPLOY_DIR/  # Copy database

cd $DEPLOY_DIR
zip -r ../$BUILD_ID.zip * # Generate archive
cd ..

# Cleanup temporary files
rm -rf database/
rm -rf capstone/
rm -rf ogdf/
rm -rf *.o
rm Makefile
rm -rf $DEPLOY_DIR

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
    git push --quiet origin builds > /dev/null 2>&1 
fi