%PYTHONHOME%\scripts\virtualenv env
call env\scripts\activate.bat
pip install . --use-mirrors
pip install pydes --use-mirrors
pip install coverage --use-mirrors
pip install nose --use-mirrors
python -m unittest discover
