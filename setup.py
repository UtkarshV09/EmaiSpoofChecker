from setuptools import setup, find_packages

setup(
    name="EmailSpoofChecker",
    version="0.1",
    description="A tool for checking SPF and DMARC records of a domain to detect email spoofing",
    packages=find_packages(),
    install_requires=["dnslib>=0.9.16", "dnspython>=2.1.0"],
    entry_points={"console_scripts": ["spoof-checker = spoof_checker.__main__:main"]},
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
    ],
    author="Utkarsh Vishwakarma",
    author_email="utkarsh.vishwakarma2909@gmail.com",
    license="MIT",
    keywords=["email", "spoofing", "SPF", "DMARC", "security"],
    url="https://github.com/UtkarshV09/EmaiSpoofChecker",
)
