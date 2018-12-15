#! /usr/bin/python3

import shutil
import os
from deploy_vars import *

shutil.make_archive(BUILD_ARCHIVE, "zip")

if not os.path.isfile(BUILD_ARCHIVE):
    print("Cannot find " + BUILD_ARCHIVE)
    exit(1)

shutil.move(BUILD_ARCHIVE, "..")
