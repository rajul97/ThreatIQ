@echo off
echo Copying all updated ThreatIQ files to Desktop...

set SRC=C:\Users\Admin\Documents\Claude\Projects\Threat Iq
set DST=C:\Users\Admin\Desktop\Threat Iq

copy /Y "%SRC%\frontend\index.html"         "%DST%\frontend\index.html"
copy /Y "%SRC%\backend\analyzer.py"          "%DST%\backend\analyzer.py"
copy /Y "%SRC%\backend\app.py"               "%DST%\backend\app.py"
copy /Y "%SRC%\backend\ioc_extractor.py"     "%DST%\backend\ioc_extractor.py"
copy /Y "%SRC%\backend\pdf_generator.py"     "%DST%\backend\pdf_generator.py"
copy /Y "%SRC%\backend\sigma_generator.py"   "%DST%\backend\sigma_generator.py"
copy /Y "%SRC%\backend\requirements.txt"     "%DST%\backend\requirements.txt"
copy /Y "%SRC%\backend\database.py"          "%DST%\backend\database.py"

echo.
echo Done! All files copied successfully.
pause
