# FolderEncryptor

[![Latest Release](https://img.shields.io/github/v/tag/kocburak/FolderEncryptor?label=release)](https://github.com/kocburak/FolderEncryptor/releases/latest)

FolderEncryptor is a tool to enable you to encrypt a whole folder, hence the name.

## Table of Contents
* [Commands](#commands)
* [Usage](#usage)
* [Building](#building)
* [Road Map](#road-map)
* [IMPORTANT NOTE!](#important-note)


# Commands

**The command `FolderEncryptor.exe --help` lists the available commands and `FolderEncryptor.exe <command> --help` shows more details for an individual command.**

| Command        | Description                    |
| -------------- | ------------------------------ |
| **list**       | Descrpyt and list filenames.   |
| **enc**        | Encrypt the spesified target.  |
| **dec**        | Decrypt the spesified target.  |
| **analyze**    | Analyze the spesified target.  |


# Usage

Simplest way to encrypt your folder is:
```
FolderEncryptor.exe enc --dir C:\input-folder --desDir C:\encrypted-folder 
```

For additional security we highly recomend the usage of `--enc-filenames` flag
```
FolderEncryptor.exe enc --dir C:\input-folder --desDir C:\encrypted-folder --enc-filenames
```

And to decrypt your folder:
```
FolderEncryptor.exe dec --dir C:\encrypted-folder --desDir C:\decrypted-folder 
```

If `--enc-filenames` flag is used then you must also provide when decrypting:
```
FolderEncryptor.exe dec --dir C:\encrypted-folder --desDir C:\decrypted-folder --enc-filenames
```

If you only want to decrypt and see the filenames:
```
FolderEncryptor.exe list --dir C:\input-folder
```
You don't need to set `--enc-filenames` flag since this command is already implies it.

# Building

### Prerequisite

* Visual Studio Version 17
* .NET 6 SDK

# Road Map

- Option to securely erase unencrypted files. (looking at you Gutmann Algorithm 👀).
- Option to overwrite the original file to erase unencrypted data. (This may be not possible if `--enc-filenames` flag is set)
- Option to output a single encrypted file for whole folder (Something like [gzip]( https://git.savannah.gnu.org/cgit/gzip.git)).
- A way to use the files without decrypting to file system first. (A Virtual file system might sufficient)
- When the structure and content of the tool is finalized, proper OOP standard must be used for the source code.

# IMPORTANT NOTE!

When you encrypt your folder and than delete the old folder. Keep in mind that it can still be **recovered**! We are planning to include secure delete of the folder bu meanwhile you must use a 3rd Party tool for that such as Microsoft's [Sysinternals SDelete](https://learn.microsoft.com/tr-tr/sysinternals/downloads/sdelete) for Windows 10 and up.
