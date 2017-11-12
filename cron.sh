#!/bin/sh

date >> cron.log
. venv/bin/activate
python3 delete-expired.py >> cron.log 2>&1
python3 email-updates.py >> cron.log 2>&1

