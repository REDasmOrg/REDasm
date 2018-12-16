import subprocess
import shutil
import os
from deploy_vars import *

LINUXDEPLOYQT_CMD = "linuxdeployqt-5-" + ARCH + ".AppImage"
LINUXDEPLOYQT_URL = "https://github.com/probonopd/linuxdeployqt/releases/download/5/" + LINUXDEPLOYQT_CMD

os.chdir("../deploy")

if not os.path.exists("REDasm"):
 print("Skipping AppImage creation")
 exit(1)

shutil.rmtree("lib", ignore_errors=True)
os.mkdir("lib")
shutil.move("LibREDasm.so", "lib/")

shutil.copy("../artwork/logo.png", "./")
shutil.copy("../ci/REDasm.desktop", "./")
os.chdir("..")

if not os.path.exists(LINUXDEPLOYQT_CMD):
 subprocess.run(["wget", "-c", LINUXDEPLOYQT_URL])

if os.path.exists(LINUXDEPLOYQT_CMD):
 subprocess.run(["chmod", "a+x", LINUXDEPLOYQT_CMD])
 os.chdir("deploy")
 subprocess.run(["../" + LINUXDEPLOYQT_CMD, "REDasm", "-appimage", "-bundle-non-qt-libs"])
 shutil.move("REDasm-" + ARCH + ".AppImage", "../")
else:
 print("linuxdeployqt not found, skipping AppImage creation")

