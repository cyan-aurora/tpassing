#!/bin/sh

virtualenv -p python3 venv
. venv/bin/activate
pip3 install -r requirements.txt
python post-setup.py
mv dummy-config.ini secure.ini
