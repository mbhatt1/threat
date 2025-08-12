#!/usr/bin/env python3
"""
Security Audit Framework Setup Configuration
"""

from setuptools import setup, find_packages
import os

# Read the README file
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Read requirements from requirements.txt
def read_requirements(filename):
    with open(filename, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]

# Get the absolute path to the directory containing this setup.py file
here = os.path.abspath(os.path.dirname(__file__))

# Read version from a VERSION file or define it here
VERSION = "1.0.0"

setup(
    name="security-audit-framework",
    version=VERSION,
    author="Security Team",
    author_email="security@example.com",
    description="A comprehensive AI-powered security audit framework for AWS environments",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/example/security-audit-framework",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.9",
    install_requires=read_requirements("requirements.txt"),
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "pytest-mock>=3.12.0",
            "pytest-asyncio>=0.21.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.5.0",
            "pre-commit>=3.3.0",
        ],
        "cdk": [
            "aws-cdk-lib>=2.100.0",
            "constructs>=10.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "security-audit=cli.main:cli",
            "saf-cli=cli.main:cli",
        ],
    },
    package_data={
        "": ["*.yaml", "*.yml", "*.json", "*.txt"],
    },
    include_package_data=True,
    zip_safe=False,
)