#! /bin/sh

LINUXDEPLOYQT_ARCH=`uname -m`
LINUXDEPLOYQT_VER="continuous"
LINUXDEPLOYQT_CMD="linuxdeployqt-$LINUXDEPLOYQT_VER-$LINUXDEPLOYQT_ARCH.AppImage"
LINUXDEPLOYQT_URL="https://github.com/probonopd/linuxdeployqt/releases/download/$LINUXDEPLOYQT_VER/$LINUXDEPLOYQT_CMD"

cd ..

if [ ! -f $LINUXDEPLOYQT_CMD ]; then
    wget -c $LINUXDEPLOYQT_URL
fi

if [ -f $LINUXDEPLOYQT_CMD ]; then
    chmod a+x ./$LINUXDEPLOYQT_CMD
    cd deploy
    VERSION="" ../$LINUXDEPLOYQT_CMD REDasm -appimage -exclude-libs=libnss.so,libnssutil3.so
    mv REDasm-*.AppImage ../
    cd ..
else
    echo "$LINUXDEPLOYQT_CMD not found, skipping AppImage creation"
fi

cd build
