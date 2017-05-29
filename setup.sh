#!/bin/sh

continue_prompt()
{
  while true; do
    read -p "Continue? [y/n] " yn
    case $yn in
      [Yy]* ) echo "Proceeding."; echo "$1"; break;;
      [Nn]* ) echo "Skipping.";   $2; break;;
      * )     echo "Please answer y or n";;
    esac
  done
}

echo "This will set up a python virtualenv."
continue_prompt "virtualenv -p python3 venv"
. venv/bin/activate
echo "This will install the requirements."
continue_prompt "pip3 install -r requirements.txt"
echo "This will install the dummy secure config because the real one could not
be transmitted."
continue_prompt "mv dummy-secure.ini secure.ini"
echo "This will set up the tables on the database you should have created."
continue_prompt "python post-setup.py"
echo "Done! If this is inprod you will probably want to run setup-cron.sh"
