#!/bin/sh

(. venv/bin/activate) || true
python3 delete-expired.py > delete-expired.log
