# 4NXCI-2026

This project is based on the work of [4NXCI](https://github.com/tiliarou/4NXCI) by The-4n.

A modernized version for Visual Studio 2026 with performance improvements and updated dependencies.

**Note:** This tool processes individual XCI files. To process an entire folder of XCI files, use [ConvertXciToNsp](https://github.com/tetj/ConvertXciToNsp) which provides batch processing functionality.

## Improvements

### Enhanced File Naming Format

NSP files are now organized with descriptive names and proper categorization:

- **Base Games**: `GameTitle[TitleID][BASE].nsp`
- **Updates/Patches**: `GameTitle[TitleID][v65536][UPD].nsp`
- **DLC/Add-ons**: `GameTitle[TitleID][DLC].nsp`

All NSP files are automatically organized into a folder named after the game title. The source XCI file is kept by default unless the `-d` flag is specified.

**Example folder structure:**

```
4nxci.exe -c "The Legend of Zelda BOTW.xci"

The Legend of Zelda - Breath of the Wild/
├── The Legend of Zelda - Breath of the Wild[01007EF00011E000][BASE].nsp
├── The Legend of Zelda - Breath of the Wild[01007EF00011E000][v196608][UPD].nsp
└── The Legend of Zelda - Breath of the Wild[01007EF00011E000][DLC].nsp
```

### Performance Enhancements

- Multi-threaded processing for applications, patches, and add-ons
- Optimized file I/O with 16MB buffering for XCI files
- Parallel extraction when multiple CPU cores are available

## Usage

**Recommended usage (2026):**
```
.\4nxci.exe -c <path_to_file.xci>
```
Add `-d` to delete the source XCI file after conversion:
```
.\4nxci.exe -c -d <path_to_file.xci>
```

**Rename existing NSP/NSZ files:**
```
.\4nxci.exe -r <path_to_file.nsp>
.\4nxci.exe -r <path_to_file.nsz>
```
This will rename the NSP or NSZ file to match the naming format based on its internal metadata (Title ID, version, type). The original extension is preserved in the output filename.

**Title name database:**

The tool relies on `US.en.json` (blawar's [titledb](https://github.com/blawar/titledb)) to resolve Title IDs to game names. It is **automatically downloaded** (~77 MB) the first time `-r` is used, and refreshed automatically when the local copy is older than 7 days.

The tool will automatically:
1. Look up the title name from the database using the Title ID
2. Fall back to using the Title ID if not found (e.g., Japan-exclusive titles, homebrew, unofficial releases)
The Title ID is used as the name instead:

```
010044901C5C2000[010044901C5C2000][BASE].nsp
```
**Full command syntax (LEGACY/DEPRECATED):**
```
.\4nxci.exe [options...] <path_to_file.xci>

Options:
-k, --keyset             Set keyset filepath, default filepath is .\keys.dat
-h, --help               Display usage
-t, --tempdir            Set temporary directory path
-o, --outdir             Set output directory path
-e, --extract            Use Titlename instead of Titleid in nsp name
-d, --delete             Delete source XCI file after successful conversion
--keepncaid              Keep current ncas ids
```

**Required Keys:**

The tool will automatically search for key files in this order:
1. `keys.dat`
2. `keys.txt`
3. `keys.ini`
4. `prod.keys` (recommended - standard output from lockpick_rcm)

Place one of these key files in the same directory as the executable, or specify a custom path with the `-k` option.

**Note:** You can obtain `prod.keys` from your Nintendo Switch using Lockpick_RCM.

## Licensing

This software is licensed under the terms of the ISC License.  
You can find a copy of the license in the LICENSE file.
