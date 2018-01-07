$archive = $env:appveyor_build_version + ".zip"

cd release
mkdir deploy

Copy-Item REDasm.exe deploy
Copy-Item ..\database deploy\database -recurse
cd deploy
windeployqt --release REDasm.exe

7z a -tzip $archive *
Move-Item -Path $archive -Destination ..\..

cd ..
Remove-Item deploy -Recurse -Force 
cd ..