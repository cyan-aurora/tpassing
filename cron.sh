#!/bin/sh

date >> cron.log
. venv/bin/activate
python3 delete-expired.py >> cron.log
python3 email-updates.py >> cron.log
