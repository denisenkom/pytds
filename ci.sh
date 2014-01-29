#!/bin/bash
set -e

$PYTHONHOME/bin/virtualenv env
. env/bin/activate
pip install coverage --use-mirrors
pip install -r requirements.txt --use-mirrors
pip install -r test_requirements.txt --use-mirrors
pip install -r test_requirements26.txt --use-mirrors || true
nosetests --with-coverage --cover-erase --cover-package=pytds --cover-xml --cover-xml-file=coverage.xml --with-xunit --xunit-file=xunit.xml
