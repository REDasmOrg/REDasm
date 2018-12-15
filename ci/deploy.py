import subprocess
import shutil
import os
from deploy_vars import *
 
res = subprocess.run(["git", "clone", "-b", "nightly", BUILD_REPO])

if res.returncode != 0:
    print("Failed to clone repo")
    exit(2)

# Cleanup old *OS_NAME* archives
files = os.listdir(BUILD_REPO)

for file in files:
    if str.find(file, OS_NAME) == -1:
        continue
    os.remove(os.path.join(BUILD_REPO, file))

shutil.move(BUILD_ARCHIVE, BUILD_REPO)
os.chdir(BUILD_REPO)

subprocess.run(["git", "config", "user.email", "buildbot@none.io"])
subprocess.run(["git", "config", "user.name", "Travis Build Bot"])
subprocess.run(["git", "add", "-A", "."])
subprocess.run(["git", "commit", "-m", "Updated " + OS_NAME + " Nightly " + BUILD_DATE])
subprocess.run(["git", "push", "--quiet", "origin", "nightly"])

