[![PyPI Version](https://img.shields.io/pypi/v/ThreatHunter)](https://pypi.org/project/ThreatHunter)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://opensource.org/licenses/GPL-3.0)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![Build Status](https://img.shields.io/github/actions/workflow/status/skye-cyber/ThreatHunter/ci.yml?branch=main)](https://github.com/skye-cyber/ThreatHunter/actions)

# ThreatHunter
A python malware detection, analysis and reverse ngineering toolkit.
This is a Linux command-line interface (CLI) utility that use YARA , Capstone ,Redare2 among otheres to detect analyze and reverse engineer malware.
This is still a work in progress version, great things are underway.

---

## Table of Contents

1. [Features](#features)  
2. [Prerequisites](#prerequisites)  
3. [Installation](#installation)  
4. [Usage](#usage)  
   - [Options](#options)  
   - [Examples](#examples)  
5. [Custom Rules](#custom-rules)  
6. [Contributing](#contributing)  
7. [License](#license)  
8. [Acknowledgements](#acknowledgements)  

---

## Features

- **YARA‑powered**: Pattern‑based detection using customizable YARA rules.  
- **Capstone Disassembly**: Decode binaries into human‑readable assembly.  
- **Radare2 Integration**: Advanced reverse‑engineering workflows.  
- **Recursive Scanning**: Analyze entire directories or individual files.  
- **Custom Rule Management**: Add or exclusively use specific YARA rule sets.  
- **Verbose Mode**: Detailed output to trace each analysis step.

---

## Prerequisites

- **Python 3.8+**  
- **pip** (Python package manager)  
- **YARA** (often via `pip install yara-python` or your distro’s package manager)  
- **Capstone** (via `pip install capstone`)  
- **Radare2** (installable via `apt`, `brew`, or from [Radare2’s site](https://rada.re/n/))

---

## Installation

### From PyPI
```shell
pip install ThreatHunter
```
### From GitHub (latest development)

```shell
pip install git+https://github.com/skye-cyber/ThreatHunter.git
```
## Usage

To run the CLI app, use the following command:

```shell
ThreatHunter [OPTIONS]
```

Replace `[options]` with the appropriate command-line options.

## Options

| Flag                  | Description                                           |
|-----------------------|-------------------------------------------------------|
| `-p`, `--path <file folder>` | Path to directory or file to scan                   |
| `-v`, `--verbose`           | Enable verbose output (disables screen-clearing between results) |
| `-a`, `--add <rule>`        | Add a custom YARA rule file, directory, or inline rule |
| `-u`, `--use <rule>`        | Use only the specified rule (requires --path)        |
| `-h`, `--help`              | Show full help and exit                               |


## Help output
```shell
ThreatHunter --help
```
## Examples

1. Scan the Documents directory
#### Unix

   ```shell
   ThreatHunter -p /home/user/Documents/
   ```

   ```shell
   ThreatHunter -p /home/user/Documents/ -v
   ```

#### win:
  
   ```shell
   ThreatHunter -p \path\toDocuments\
   ```
  The toolkit will scan all the files and folder in the `/home/user/Documents/` directory and it's nested
  files and folders to the last child.
  `-p` also accepts file input

2. Scan working directory
   ```shell
   ThreatHunter
   ```
3. Scan current directory in verbose mode
   ```shell
   ThreatHunter -v
   ```
Giving no option as in the above case, the toolkit will recursively scan the current directory (working directory)

## Adding rule(s) to the existing rules
```shell
ThreatHunter --add @foo
```
where ``@foo`` is the rule file, folder or even rule in text form

## Using exclusive rule
You may also want to rune scan using a given rule only, that case, you can follow this format
```shell
ThreatHunter --use @foo -p
```
where ``@foo`` is the rule file, folder or rule itself.
if ``-u/--use`` is used, then ``-p/--path`` must be provided
## Contributing
Feel free to submit any suggestions!

Contributions are welcome! If you encounter any issues or have suggestions for improvements, please open an issue or submit a pull request.

## License

This project is an open source software. Under GPL-3.0 license


Feel free to modify and customize this template according to your specific project requirements and add any additional sections or information that you think would be helpful for users.

