#!/bin/bash
set -e

# this fixes python-dateutil installation on python3
export PYTHONIOENCODING=utf8 LC_ALL=en_US.UTF-8

$PYTHONHOME/bin/virtualenv env
. env/bin/activate
pip install pydes --use-mirrors
pip install coverage --use-mirrors
pip install nose --use-mirrors
pip install -e .
nosetests --with-coverage --cover-package=pytds --cover-xml --cover-xml-file=coverage.xml --with-xunit --xunit-file=xunit.xml
