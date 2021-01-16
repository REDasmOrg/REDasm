## Requirements for all platforms
* CMake >= 3.12
* Qt >= 5.11
* C++17 capable compiler
  * Tested with GCC 8.3 on Linux
  * Tested with Visual Studio 2019 on Windows
* Git
****
### 1. Pre-Build steps for Windows
Open a Command Prompt and execute:
```bash
call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat"
set CMAKE=C:\Qt\Tools\CMake_64\bin
set QTCREATOR=C:\Qt\Tools\QtCreator\bin
set QTDIR=C:\Qt\5.12\msvc2019_64\bin # Change this to your Qt Version
set PATH=%QTDIR%;%CMAKE%;%QTCREATOR%;%PATH%
```

### 2. Compiling REDasm with CMake

```bash
git clone --recursive https://github.com/REDasmOrg/REDasm.git
cd REDasm
mkdir build
cd build
cmake ..
cmake --build . -jN --config Release # N=number of cores (-j4, -j8, ...)
cmake --install . --prefix deploy --config Release
```

### 3. Post-Build steps for Windows
```bash
cd deploy
windeployqt .
```
