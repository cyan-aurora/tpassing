#!/usr/bin/env python3

# DO NOT RUN THIS SCRIPT
# It is run from setup.sh when setting up for the first time

from main import db
db.create_all()
