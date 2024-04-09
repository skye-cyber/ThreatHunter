# MalwareDART
A python malware detection, analysis and reverse ngineering toolkit( `MalwareDART``)
This is a Linux command-line interface (CLI) utility that use YARA , Capstone ,Redare2 among otheres to detect analyze and reverse engineer malware.
This is still a work in progress version, great things are underway.

## Installation

1. Clone the repository:

   ```shell
   git clone https://github.com/skye-cyber/MalwareDART.git
   ```

2. Navigate to the project directory:

   ```shell
   cd MalwareDART
   ```

3. Install the package:
   ```shell
   pip install -e .
   ```

## Usage

To run the CLI app, use the following command:

```shell
MDART [option]
```

Replace `[options]` with the appropriate command-line options.

## Available Options

- `-p/--path`:path to directory or file to scan
- `-v/--verbose`: Show all infor. By default screen clering is on so only one line of output show per time,
pass verbose to prevent screen cleaning.
verbose mode can be useful when work to e done is minimal

## Examples

1. Example command 1:

   ```shell
   MDART -p /home/user/Documents/
   ```

   ```shell
   MDART -p /home/user/Documents/ -v
   ```

  The toolkit will scan all the files and folder in the `/home/user/Documents/` directory and it's nested
  files and folders to the last child.
  `-p` also accepts file input

2. Scan working directory
   ```shell
   MDART
   ```
   ```shell
   MDART -v
   ```
Giving no option as in the above case, the toolkit will recursively scan the current directory (working directory)

## Contributing
Feel free to submit any suggestions!

Contributions are welcome! If you encounter any issues or have suggestions for improvements, please open an issue or submit a pull request.

## License

This project is an open source software. Under GPL-3.0 license


Feel free to modify and customize this template according to your specific project requirements and add any additional sections or information that you think would be helpful for users.

