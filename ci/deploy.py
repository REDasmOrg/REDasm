import subprocess
import shutil
import base64
import os
from tempfile import NamedTemporaryFile
from deploy_vars import *

def do_deploy(filename):
 fp = NamedTemporaryFile(delete=False)
 fp.write(base64.b64decode(os.getenv("DEPLOY_TOKEN")))
 fp.close();
 subprocess.run(["scp", "-oStrictHostKeyChecking=no", "-i", [fp.name], filename, os.getenv("DEPLOY_DESTINATION")])
 os.remove(fp.name)

os.chdir("..")

if OS_NAME == "Linux":
 appimagename = "REDasm_" + ARCH  + "_" + BUILD_DATE + ".AppImage"
 shutil.move("REDasm--" + ARCH + ".AppImage", appimagename)
 do_deploy(appimagename)

do_deploy(BUILD_ARCHIVE)
