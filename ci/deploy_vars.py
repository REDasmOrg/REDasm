import subprocess
import platform
import sys
import os
from datetime import datetime

OS_NAME           = sys.platform
ARCH              = platform.machine()

if OS_NAME.startswith("linux"):
    OS_NAME = "Linux"
elif OS_NAME.startswith("darwin"):
    OS_NAME = "Darwin"
elif (OS_NAME == "win32") or (OS_NAME == "cygwin"):
    OS_NAME = "Windows"

if ARCH == "AMD64":
    ARCH = "x86_64"

BUILD_DATE        = datetime.now().strftime("%Y%m%d")
BUILD_ID          = "REDasm_" + OS_NAME + "_" + ARCH  + "_" + BUILD_DATE
BUILD_ARCHIVE     = BUILD_ID + ".zip"
BUILD_REPO        = "REDasm-Builds"
DATABASE_REPO_URL = "https://github.com/REDasmOrg/REDasm-Database.git"
