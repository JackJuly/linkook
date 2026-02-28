#!/usr/bin/env python3

import os
from setuptools import setup, find_packages

# Read long description
root_dir = os.path.abspath(os.path.dirname(__file__))
long_description = "Linkook is an OSINT tool for discovering linked/connected social accounts and associated emails across multiple platforms using a single username. It also supports exporting the gathered relationships in a Neo4j-friendly format for visual analysis."
readme_path = os.path.join(root_dir, "README.md")

if os.path.isfile(readme_path):
    with open(readme_path, "r", encoding="utf-8") as fh:
        long_description = fh.read()

setup(
    name="linkook",
    version="1.1.2",
    author="Jack Ju1y",
    author_email="ju1y0x0@proton.me",
    description="A tool for scanning and enumerating linked social accounts.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/JackJuly/linkook",
    license="MIT",
    packages=find_packages(),
    include_package_data=True,
    package_data={
        "linkook.provider": ["provider.json"],
    },
    python_requires=">=3.7",
    install_requires=[
        "requests>=2",
        "colorama>=0.4.6"
    ],
    entry_points={
        "console_scripts": [
            "linkook=linkook.linkook:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
)
