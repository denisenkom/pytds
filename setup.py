import os
import setuptools
from setuptools import setup
import version

requirements = list(
    open(os.path.join(os.path.dirname(__file__), "requirements.txt"), "r").readlines()
)

print(setuptools.find_packages("src"))

setup(
    name="python-tds",
    version=version.get_git_version(),
    description="Python DBAPI driver for MSSQL using pure Python TDS (Tabular Data Stream) protocol implementation",
    author="Mikhail Denisenko",
    author_email="denisenkom@gmail.com",
    url="https://github.com/denisenkom/pytds",
    license="MIT",
    packages=["pytds"],
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    zip_safe=True,
    install_requires=requirements,
)
