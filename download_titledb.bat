@echo off
echo Downloading Nintendo Switch title database...
echo.
powershell -Command "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/blawar/titledb/master/US.en.json' -OutFile 'US.en.json'"
if exist titles.us.en.json (
    echo.
    echo Successfully downloaded titles.us.en.json
    echo This file contains title names for NSP renaming feature.
) else (
    echo.
    echo Failed to download title database.
    echo Please download manually from: https://github.com/blawar/titledb
)
pause
