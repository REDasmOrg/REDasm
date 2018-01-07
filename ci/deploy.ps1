$archive = $env:appveyor_build_version + ".zip"

git config core.autocrlf true
git config --global credential.helper store
Add-Content "$env:USERPROFILE\.git-credentials" "https://$($env:github_token):x-oauth-basic@github.com`n"

if(Test-Path $($env:build_repo)) {
    Remove-Item $($env:build_repo) -Recurse -Force 
}

git clone -b nightly https://$($env:github_token)@github.com/REDasmOrg/$($env:build_repo).git > $null 2>&1
cd $($env:build_repo)
Remove-Item *Windows* 
    
if(Test-Path ../$archive)
{
    Move-Item -Path ../$archive -Destination .
    git config --global user.email "buildbot@none.io"
    git config --global user.name "AppVeyor Build Bot"
    git add -A .
    git commit -m "Updated Windows Nightly $(Get-Date -format ddMMyyyy)"
    git push --quiet origin nightly > $null 2>&1 
}