@echo off
:: siehe: https://ib-aid.com/articles/wie-analysiert-man-firebird-traces-mit-ibsurgeon-performance-analysis
SET "MYPASS=masterkey"
SET "MYPFAD=C:\Program Files\Firebird\Firebird_4_0_3"

SET "MYTRACEID=6"
echo Bitte ermittle die Trace ID aus dem Kopf der Log Datei unter %LOGOUTPUT% und trage es hier in der Batchdatei ein!
echo Danach drücke die Leertaste
pause
"%MYPFAD%\fbtracemgr" -SE service_mgr -USER sysdba -PASS %MYPASS% -STOP -ID %MYTRACEID%
