@echo off
start notepad.exe
timeout /t 3
.\user_run.exe mapper.dll mapper_user_test.dll notepad.exe
pause
