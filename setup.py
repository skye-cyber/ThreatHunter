from setuptools import setup

setup(
    name='MDART',
    version='1.0',
    author="Wambua aka Bullet Angel",
    packages=["MDART"],
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    entry_points={
        'console_scripts': [
            "MDART=MDART:main"],
    },
    python_requires='>=3',
    install_requires=[
        argparse
        'yara',
        'capstone',
        'r2pipe',
        'elftools',
        'pefile',
        'progressbar'

    ],
    include_package_data=True,
    license="MIT",
    keywords='MDART', 'MalwareDART',
    classifiers=[
        "Environment :: Console",
        "Operating System :: POSIX :: Linux",
        "Operating System :: DOS :: Windows",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: Implementation :: PyPi",
    ],
)
