## Requirements for all platforms
* CMake >= 3.10
* Qt >= 5.10
* C++11 capable compiler (GCC and MSVC are supported)
****
### Building REDasm on Windows
**NOTE:** Visual Studio 2017 is required in order to compile REDasm.
<br>
Open a Command prompt and execute:
```
call "C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\VC\Auxiliary\Build\vcvars64.bat"
set QTCREATOR=C:\Qt\Tools\QtCreator\bin
set QTDIR=C:\Qt\5.10\msvc2017_64\bin
set PATH=%QTDIR%;%QTCREATOR%;%PATH%

git clone --recursive https://github.com/REDasmOrg/REDasm.git
cd REDasm
mkdir build
cd build
cmake -G "NMake Makefiles" ..
jom -jN # Or 'nmake' N=number of cores (-j4, -j8, ...)

# Extra steps for deploying REDasm in a separate folder called 'deploy'
mkdir deploy
xcopy database deploy\database\ /E
xcopy LibREDasm.dll deploy
xcopy REDasm.exe deploy
cd deploy
windeployqt --release .
```

### Building REDasm on Linux
Open a Terminal window and execute:
```
git clone --recursive https://github.com/REDasmOrg/REDasm.git
cd REDasm
mkdir build
cd build
cmake ..
make -jN # N=number of cores (-j4, -j8, ...)

# Extra steps for deploying REDasm in a separate folder called 'deploy'
mkdir deploy
cp -r database/ deploy/database/
cp LibREDasm.so deploy/
cp REDasm deploy/
```
