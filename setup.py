from setuptools import setup, find_packages

setup(
    name="quicksight-migrator",
    version="0.1.0",
    description="Automated migration tools for AWS QuickSight assets between accounts.",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="Pedro Paulo Monteiro Muniz Barbosa",
    author_email="pedropaulommb@gmail.com",
    url="https://github.com/ppedrord/quicksight-migrator",
    license="MIT",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "boto3>=1.28.0",
        "botocore>=1.31.0",
    ],
    python_requires=">=3.8",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Intended Audience :: Developers",
        "Operating System :: OS Independent",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Utilities",
    ],
    entry_points={
        "console_scripts": ["quicksight-migrator=quicksight_migrator.__main__:main"]
    },
)
