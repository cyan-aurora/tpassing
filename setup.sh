#!/bin/bash

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

# Check for python3
if [ ! -x "$(command -v python3)" ]; then
  echo "It looks like you don't have python3 installed."
  echo "On debian-like systems, you can install with:"
  echo "$ sudo apt-get install python3"
  echo "You'll also want pip:"
  echo "$ sudo apt-get install python3-pip"
  echo "The installation will be impossible without python3"
  continue_prompt 'echo "Continuing!"' exit
fi

# Check for an installed virtual environment
if [ ! -d "venv" ]; then

  if [ ! -x "$(command -v virtualenv)" ]; then
    echo "It looks like you don't have virtualenv installed. Install it? (Requires sudo)"
    continue_prompt "sudo pip install virtualenv" exit
  fi

  # No reason to ask; at the worst they `rm -r` venv
  echo "Setting up a virtual environment..."
  virtualenv -p python3 venv
  echo

fi

# Safe if activated twice
echo "Activating virtual environment."
. venv/bin/activate
echo

echo "This will install the requirements for the website."
continue_prompt "pip3 install -r requirements.txt"
echo

echo "You should have installed mysql. You'll need to enter your password so
the website can access it. Enter nothing to skip this step."
echo -n "Password: "
stty -echo
read password
stty echo
echo
if [ ! -z "$password" ]; then
  # If they entered a password they surely want to move the dummy. If they
  # haven't what's the point? So no need for confirmation; we can safely put
  # this here.
  # secure.ini is in .gitignore so it's safe
  cp dummy-secure.ini secure.ini
  # Replace spaces with %20 (url-encode). We escape the % for both INI format
  # and sh, resulting in 4:1 ratio
  escaped_password=${password// /%%%%20}
  printf "\n[SQL]\npassword=$escaped_password\n" >> secure.ini
else
  echo "Skipping, but the rest of setup requires a password to be entered in secure.ini"
fi
echo

python setup-database.py
echo

echo "Done!"
