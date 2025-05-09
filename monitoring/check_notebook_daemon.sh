#!/bin/bash

LOG_FILE="/tmp/notebook_daemon_monitor.log"
DATE=$(date '+%Y-%m-%d %H:%M:%S')
if pgrep -f run_zero-ai-daemoned.py > /dev/null; then
    echo "$DATE - Notebook daemon is running." >> "$LOG_FILE"
else
    echo "$DATE - Notebook daemon is NOT running!" >> "$LOG_FILE"
fi


# crontab -e
# 0 */4 * * * /tmp/check_notebook_daemon.sh