@echo off
REM The single development launcher for Compakt, both front ends.
REM Copyright (c) 2026 Rounak Miskin (Founder: Kasanki Labs)
REM
REM   compakt.bat                     opens the desktop window
REM   compakt.bat formats             runs the command line
REM   compakt.bat c src -o out.pakt
REM   compakt.bat x out.pakt -d dest
REM
REM No arguments means the window; any argument means the CLI. One file
REM rather than two, because two launchers sitting beside each other is
REM how four of them ended up scattered across the tree.
REM
REM Uses the project's virtual environment, never whatever python is on
REM PATH -- the system interpreter has none of the dependencies and
REM fails confusingly on `import libarchive`.
REM
REM NOTE: the SHIPPED command line is called `pakt`, not `compakt` --
REM the installer puts pakt.exe on PATH. This file is a development
REM shim only, and the difference is deliberate rather than an
REM oversight.

setlocal
set "REPO=%~dp0"
set "PY=%REPO%.venv\Scripts\python.exe"

if not exist "%PY%" (
  echo.
  echo   The project virtual environment is missing.
  echo   Create it once with:
  echo.
  echo     cd /d "%REPO%"
  echo     python -m venv .venv
  echo     .venv\Scripts\python.exe -m pip install -r requirements-dev.txt
  echo.
  pause
  exit /b 1
)

pushd "%REPO%"

REM Dispatch with goto rather than an if/else block: inside a
REM parenthesised block cmd expands %ERRORLEVEL% at PARSE time, so the
REM exit code captured there is always the one from before the command
REM ran. The CLI's exit codes are a documented scripting contract and
REM must survive this shim intact.
if "%~1"=="" goto :window

"%PY%" pakt.py %*
set CODE=%ERRORLEVEL%
goto :done

:window
"%PY%" compakt.py
set CODE=%ERRORLEVEL%
REM Pause only on failure, so a double-click does not close the console
REM before the traceback can be read.
if not "%CODE%"=="0" pause

:done
popd
endlocal & exit /b %CODE%
