@echo off
gcc -O2 -std=c11 -Wall -Wextra -D_WIN32_WINNT=0x0A00 main.c edr.c logger.c process.c scanner.c monitor.c vt.c -o MiniEDR.exe -lbcrypt -lwintrust -lws2_32 -lwinhttp
if errorlevel 1 (echo BUILD FAILED) else (echo BUILD OK)
