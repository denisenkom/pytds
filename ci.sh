#!/bin/bash
$PYTHONHOME/bin/virtualenv env
. env/bin/activate
pip install pydes --use-mirrors
pip install coverage --use-mirrors
pip install nose --use-mirrors
nosetests --with-coverage --cover-package=pytds --cover-xml --cover-xml-file=coverage.xml --with-xunit --xunit-file=xunit.xml
