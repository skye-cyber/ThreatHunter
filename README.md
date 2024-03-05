# MalwareDART
A python malware detection analysis and reverse ngineering toolkit( ``MalwareDART``)
`This is a Linux command-line interface (CLI) utility that use YARA , Capstone ,Redare2 among otheres to detect analyze and reverse engineer malware.

## Installation

1. Clone the repository:

   ```shell
   git clone https://github.com/skye-cyber/MalwareDART
   ```

2. Navigate to the project directory:

   ```shell
   cd MalwareDART
   ```

3. Install the required dependencies:

   ```shell
   pip install -r requirements.txt
   ```
4.Install the package:
   ```shell
   pip install ./
   ```

## Usage

To run the CLI app, use the following command:

```shell
MDART [option]
```

Replace `[options]` with the appropriate command-line options.

## Available Options

- `-P/--path`:path to directory or file to scan

## Examples

1. Example command 1:

   ```shell
   MDART -P /home/user/Documents/
   ```

  The toolkit will scan all the files and folder in the `/home/user/Documents/` directory and it's nested
  files and folders to the last child.

2. Scan working directory
   ```shell
   MDART
   ```
Giving no option as in the above case, the toolkit will recursively scan the current directory (working directory)

## Contributing
Feel free to submit any suggestions!

Contributions are welcome! If you encounter any issues or have suggestions for improvements, please open an issue or submit a pull request.

## License

This project is an open source software. Under GPL-3.0 license


Feel free to modify and customize this template according to your specific project requirements and add any additional sections or information that you think would be helpful for users.

