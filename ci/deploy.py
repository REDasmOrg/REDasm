import subprocess
import shutil
import os
from deploy_vars import *

# Cleanup old *wildcard* archives
def build_repo_delete_all(wildcard):
 files = os.listdir(BUILD_REPO)
 for file in files:
    if str.find(file, wildcard) == -1:
        continue
    os.remove(os.path.join(BUILD_REPO, file))
 
os.chdir("..")
res = subprocess.run(["git", "clone", "-b", "nightly", BUILD_REPO_URL])

if res.returncode != 0:
    print("Failed to clone repo")
    exit(2)

build_repo_delete_all(OS_NAME)
shutil.move(BUILD_ARCHIVE, BUILD_REPO)

if OS_NAME == "Linux":
 build_repo_delete_all("AppImage")
 shutil.move("REDasm--" + ARCH + ".AppImage", BUILD_REPO + "/REDasm_" + ARCH  + "_" + BUILD_DATE + ".AppImage")

os.chdir(BUILD_REPO)

subprocess.run(["git", "config", "user.email", "buildbot@none.io"])
subprocess.run(["git", "config", "user.name", "Travis Build Bot"])
subprocess.run(["git", "add", "-A", "."])
subprocess.run(["git", "commit", "-m", "Updated " + OS_NAME + " Nightly " + BUILD_DATE])
subprocess.run(["git", "push", "--quiet", "origin", "nightly"])

