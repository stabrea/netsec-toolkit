"""Package setup for netsec-toolkit."""

from setuptools import setup, find_packages

with open("README.md", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="netsec-toolkit",
    version="1.0.0",
    author="Taofik Bishi",
    description="A network security scanning toolkit for reconnaissance and vulnerability assessment",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/taofikbishi/netsec-toolkit",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "rich>=13.0.0",
    ],
    entry_points={
        "console_scripts": [
            "netsec=netsec_toolkit.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: Education",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Topic :: Security",
        "Topic :: System :: Networking",
        "Topic :: Utilities",
    ],
    keywords="security, network, scanner, vulnerability, pentest, reconnaissance",
)
