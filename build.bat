@echo off
gcc main.c edr.c logger.c process.c scanner.c monitor.c -Wall -Wextra -std=c11 -o MiniEDR.exe
if errorlevel 1 (echo BUILD FAILED) else (echo BUILD OK)
pause
