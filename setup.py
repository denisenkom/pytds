import os
from distutils.core import setup

requirements = list(open(os.path.join(os.path.dirname(__file__), 'requirements.txt'), 'r').readlines())

setup(name='python-tds',
      version='1.5.0',
      description='Python DBAPI driver for MSSQL using pure Python TDS (Tabular Data Stream) protocol implementation',
      author='Mikhail Denisenko',
      author_email='denisenkom@gmail.com',
      url='https://github.com/denisenkom/pytds',
      packages=['pytds'],
      classifiers=[
          'Development Status :: 4 - Beta',
          'Programming Language :: Python',
          'Programming Language :: Python :: 2.7',
          'Programming Language :: Python :: 3.3',
      ],
      zip_safe=True,
      install_requires=requirements,
      )
