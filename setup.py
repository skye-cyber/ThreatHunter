from setuptools import find_namespace_packages, setup

setup(
    name='ThreatHunter',
    version='1.1.2',
    author="Wambua aka Bullet Angel",
    packages=find_namespace_packages(include=['*']),
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    entry_points={
        'console_scripts': [
            "ThreatHunter=ThreatHunter:main"],
    },
    python_requires='>=3',
    install_requires=[
        'argparse',
        'yara-python',
        'capstone',
        'r2pipe',
        'pyelftools',
        'pefile',
        'progressbar',
        'pymem'

    ],
    include_package_data=True,
    package_data={
        'ThreatHunter': ['rules/**/*', 'warn/**/*']
    },
    license="MIT",
    keywords=['MalwareDART', "ThreatHunter", "malware", "malware-analysis", "malware-scan", "malware-detection", "trojan", "virus"
              ],
    classifiers=[
        "Environment :: Console",
        "Operating System :: OS Independent",
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
    ],
)
