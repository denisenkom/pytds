%PYTHONHOME%\scripts\virtualenv env
set PYTHONHOME=
env\scripts\pip install coverage --use-mirrors
env\scripts\pip install -r requirements.txt --use-mirrors
env\scripts\pip install -r test_requirements.txt --use-mirrors
env\scripts\pip install -r test_requirements26.txt --use-mirrors
env\scripts\nosetests --with-coverage --cover-erase --cover-package=pytds --cover-xml --cover-xml-file=coverage.xml --with-xunit --xunit-file=xunit.xml
