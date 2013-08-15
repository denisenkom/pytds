%PYTHONHOME%\scripts\virtualenv env
call env\scripts\activate.bat
pip install pydes --use-mirrors
pip install coverage --use-mirrors
pip install -r requirements.txt --use-mirrors
pip install -r test_requirements.txt --use-mirrors
nosetests --with-coverage --cover-package=pytds --cover-xml --cover-xml-file=coverage.xml --with-xunit --xunit-file=xunit.xml
