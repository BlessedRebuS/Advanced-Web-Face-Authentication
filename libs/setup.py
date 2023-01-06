from setuptools import setup, find_packages, __version__

setup(
    name="jwtoken",
    version="1.0.0",
    packages=find_packages(),
    include_package_data=True,
    description="Custom JWT library",
    python_requires=">=3.8.*",
    install_requires=[
        "cryptography>=35.0.0",
    ],
)