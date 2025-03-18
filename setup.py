from setuptools import setup, find_packages

setup(
    name="cloud-security-scanner",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "boto3>=1.26.0",
        "pymongo>=4.5.0",
        "python-dotenv>=1.0.0",
        "requests>=2.31.0",
        "terraform-local>=0.2.1",
        "pydantic>=2.0.0",
        "pydantic-settings>=2.0.0",
    ],
    entry_points={
        "console_scripts": [
            "cloud-scanner=src.main:main",
        ],
    },
) 