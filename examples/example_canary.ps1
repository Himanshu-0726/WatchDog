# WatchDog Example Canary File
# This is an example of what a generated PS1 canary looks like.
#
# WARNING: This is a security canary file.
# If you see this message, the canary has been triggered.
# An alert has been sent to the system administrator.
#
# For authorized use only. See DISCLAIMER.md.

Start-Sleep -Seconds 2
Start-Process -FilePath "pythonw" -ArgumentList "C:\path\to\watchdog\sentinel.py"
