@echo off
:: siehe: https://ib-aid.com/articles/wie-analysiert-man-firebird-traces-mit-ibsurgeon-performance-analysis
SET "MYPASS=masterkey"
SET "MYPFAD=C:\Program Files\Firebird\Firebird_4_0_3"
SET "LOGOUTPUT=E:\trace_output.log"
SET "TRACECONFIG=%~dp0fbtrace30.cfg"
echo Bitte ermittle die Trace ID aus dem kopf der Log Datei unter %LOGOUTPUT%
"%MYPFAD%\fbtracemgr" -SE service_mgr -USER sysdba -PASS %MYPASS% -START -CONFIG %TRACECONFIG% > "%LOGOUTPUT%"
