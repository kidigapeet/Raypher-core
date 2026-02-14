& "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if ($LASTEXITCODE -eq 0) {
    & "$env:USERPROFILE\.cargo\bin\cargo.exe" build
}
