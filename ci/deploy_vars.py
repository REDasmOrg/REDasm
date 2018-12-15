import subprocess
import platform
import sys
import os
from datetime import datetime

OS_NAME        = str.capitalize(sys.platform)
ARCH           = platform.machine()
BUILD_DATE     = datetime.now().strftime("%Y%m%d")
BUILD_ID       = "REDasm_" + OS_NAME + "_" + ARCH  + "_" + BUILD_DATE
BUILD_REPO     = "REDasmOrg/REDasm-Builds"
BUILD_REPO_URL = "https://" + os.environ["GITHUB_TOKEN"] + "@github.com/" + BUILD_REPO + ".git"
BUILD_ARCHIVE  = BUILD_ID + ".zip"
