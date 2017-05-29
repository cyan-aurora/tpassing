#!/bin/sh

. venv/bin/activate
python delete-expired.py > delete-expired.log
