#!/bin/bash
set -e
$PYTHONHOME/bin/virtualenv env
. env/bin/activate
pip install pydes --use-mirrors
pip install coverage --use-mirrors
pip install nose --use-mirrors
python -m unittest discover
