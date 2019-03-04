#! /usr/bin/python3

import shutil
import os
from deploy_vars import *

shutil.rmtree("../deploy", ignore_errors=True)
os.mkdir("../deploy")

if OS_NAME == "Windows":
    shutil.copy("LibREDasm.dll", "../deploy")
    shutil.copy("REDasm.exe", "../deploy")
else if OS_NAME == "Linux":
    shutil.copy("LibREDasm.so", "../deploy")
    shutil.copy("REDasm", "../deploy")
else if OS_NAME == "Darwin":
    shutil.copy("LibREDasm.dylib", "../deploy")
    shutil.copy("REDasm", "../deploy")

os.chdir("../deploy")
res = subprocess.run(["git", "clone", DATABASE_REPO_URL, "database"])

if res.returncode != 0:
    printf("Cannot clone database")
    exit(1)

shutil.rmtree("database/.git", ignore_errors=True)

if OS_NAME == "Windows":
    subprocess.run(["windeployqt", "--release", "."])

shutil.make_archive("../" + BUILD_ID, "zip")

if not os.path.isfile("../" + BUILD_ARCHIVE):
    print("Cannot find " + BUILD_ARCHIVE)
    exit(1)
