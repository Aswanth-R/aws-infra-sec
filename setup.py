"""
Setup script for AWS InfraSec
"""
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="aws-infrasec",
    version="2.0",
    author="Aswanth",
    author_email="aswanthrajan97@gmail.com",
    description="A security scanner for AWS resources",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.9",
    install_requires=[
        "boto3>=1.20.0",
        "click>=8.0.0",
        "prettytable>=2.0.0",
        "colorama>=0.4.4",
    ],
    entry_points={
        "console_scripts": [
            "aws-infrasec=aws_infrasec.cli:main",
        ],
    },
)