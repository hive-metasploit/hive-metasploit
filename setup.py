# Description
"""
Hive Metasploit connector setup
Author: Vladimir Ivanov
License: MIT
Copyright 2021, Hive Metasploit connector
"""

# Import
from setuptools import setup, find_packages

# Authorship information
__author__ = "Vladimir Ivanov"
__copyright__ = "Copyright 2021, Hive Metasploit connector"
__credits__ = [""]
__license__ = "MIT"
__version__ = "0.0.1a1"
__maintainer__ = "Vladimir Ivanov"
__email__ = "ivanov.vladimir.mail@gmail.com"
__status__ = "Development"

# Setup
with open("README.md", "r") as readme:
    long_description = readme.read()

setup(
    name="hive-metasploit",
    version=__version__,
    author=__author__,
    author_email=__email__,
    description="Hive Metasploit connector",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://hive-metasploit.github.io/",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Education",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: English",
        "Operating System :: MacOS",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: Education",
        "Topic :: Security",
    ],
    install_requires=["hive-library", "marshmallow", "colorama", "libmsf"],
    entry_points={
        "console_scripts": ["hive-metasploit=hive_metasploit.cli:main"],
    },
    python_requires=">=3.6",
    include_package_data=True,
)
