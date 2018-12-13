from setuptools import setup
from pathlib import Path

readme = Path(__file__).with_name("README.rst").read_text()

setup(
    name="domsniff",
    version="0.2",
    description="Passive DNS sniffer for collecting domain names",
    long_description=readme,
    long_description_content_type="text/x-rst",
    url="https://github.com/oskar456/domsniff",
    author="Ondřej Caletka",
    author_email="ondrej@caletka.cz",
    license="MIT",
    py_modules=["domsniff"],
    python_requires=">=3.5",
    tests_require=["pytest"],
    entry_points={
            "console_scripts": [
                "domsniff = domsniff:main",
            ],
    },
    install_requires=[
        "click",
        "dpkt",
        "pypcap",
    ],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3 :: Only",
        "Topic :: Utilities",
    ],

)
