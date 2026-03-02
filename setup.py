#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ShadowScan - Setup Configuration
Author: Mahara HOSEN SIAM
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="shadowscan",
    version="2.0.0",
    author="Mahara HOSEN SIAM",
    author_email="mharasiam@example.com",
    description="Advanced Network Port Scanner for Penetration Testing",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/mharasiam/ShadowScan",
    project_urls={
        "Bug Tracker": "https://github.com/mharasiam/ShadowScan/issues",
        "Documentation": "https://github.com/mharasiam/ShadowScan#readme",
        "Source Code": "https://github.com/mharasiam/ShadowScan",
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Developers",
        "License :: Other/Proprietary License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: System :: Networking",
        "Topic :: System :: Systems Administration",
        "Topic :: Utilities",
    ],
    python_requires=">=3.8",
    install_requires=[
        "colorama>=0.4.6",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
        ],
    },
    py_modules=["shadowscan"],
    entry_points={
        "console_scripts": [
            "shadowscan=shadowscan:main",
        ],
    },
    keywords=[
        "port scanner",
        "network scanner",
        "penetration testing",
        "security",
        "cybersecurity",
        "network reconnaissance",
        "banner grabbing",
        "service detection",
        "ethical hacking",
        "infosec",
    ],
    license="Shadow Public License v1.0",
    include_package_data=True,
    zip_safe=False,
)
