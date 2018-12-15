import subprocess
import shutil
import os
from deploy_vars import *

LINUXDEPLOYQT_URL = "https://github.com/probonopd/linuxdeployqt/releases/download/5/linuxdeployqt-5-x86_64.AppImage"

def appdir_path(s):
 return "appdir/" + s

os.mkdir(appdir_path())
shutil.copy("REDasm", appdir_path())

os.mkdir(appdir_path("lib"))
shutil.copy("LibREDasm.so", appdir_path("lib"))
shutil.copy("../artwork/logo.png", appdir_path())
shutil.copy("../REDasm.desktop", appdir_path())
shutil.copytree("database", appdir_path())

subprocess.run(["wget", "-c", LINUXDEPLOYQT_URL])
subprocess.run(["chmod", "[a+x]", "linuxdeployqt*.AppImage"], shell=True)
subprocess.run(["linuxdeployqt*.AppImage", "appdir/REDasm", "-appimage", "-bundle-non-qt-libs"])
