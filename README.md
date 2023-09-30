# FolderEncryptor
FolderEncryptor is a tool to enable you to encrypt a whole folder, hence the name.

# Usage

Simplest way to encrypt your folder is:
```
FolderEncryptor.exe enc --dir C:\input-folder --desDir C:\encrypted-folder 
```

And to decrypt your folder:
```
FolderEncryptor.exe dec --dir C:\encrypted-folder --desDir C:\decrypted-folder 
```

For additional security we highly recomend the usage of `--enc-filenames` flag

## Commands

**The command `FolderEncryptor.exe --help` lists the available commands and `FolderEncryptor.exe <command> --help` shows more details for an individual command.**

| Command        | Description                                                                                                                                     |
| -------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| **enc**        | Encrypt the spesified target.                                                                                                                   |
| **dec**        | Decrypt the spesified target.                                                                                                                   |
| **analyze**    | Analyze the spesified target.                                                                                                                   |