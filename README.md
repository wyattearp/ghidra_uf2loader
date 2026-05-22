# Overview 
Provides a `better than raw binary loader` for UF2 files when loading them into Ghidra.
It (potentially) handles architecture detection, memory mapping, and block consolidation.
After burning some AI tokens, it's slightly better than it was.

## Key Features
* **Multi-Architecture Support:** Automatically detects target architectures using UF2 Family IDs. Supported platforms include:
  * **ARM Cortex:** RP2040, STM32, SAMD (this is the default)
  * **Xtensa:** ESP32, ESP32-S2, ESP32-S3, and ESP8266
  * **RISC-V:** ESP32-C3
  * **AVR8:** ATmega32
* **Block Merging:** UF2 files often contain fragmented blocks. This loader merges contiguous blocks into single memory segments, making analysis much cleaner.
* **FileBytes Integration:** Uses Ghidra's `FileBytes` API to maintain a backlink to the original file data, allowing for better tracking and data manipulation within Ghidra.
* **Automated Testing:** Comprehensive CI/CD via GitHub Actions with headless verification tests.

## Motivation
UF2 is the standard for modern microcontroller development (like the Raspberry Pi RP2040). While you *could* use external scripts to convert UF2 to flat binaries, doing so loses critical metadata like target addresses and architecture hints. This loader brings that intelligence directly into Ghidra, saving time and reducing friction.

## Installation
You can either install from the zip if you trust me from the [Releases](releases/latest) or you can build the code yourself.

1. Launch Ghidra: Open the main Ghidra window (the project manager).
1. Open Extension Menu: Go to File > Install Extensions....
1. Add Extension: Click the green "+" icon in the top-right corner of the window.
1. Select File: Navigate to and select the .zip file for your extension.
1. Enable & Confirm: Ensure the checkbox for your new extension is checked in the list, then click OK.
1. Restart: Ghidra will prompt you to restart for the changes to take effect

## Building the Code
You'll need Ghidra, its compatible version of gradle, and a copy of the code:

1. Clone the project
1. `gradle -PGHIDRA_INSTALL_DIR=<path to ghidra install> buildExtension`
1. Take that zip file and load it into Ghidra

## Testing
Thanks to the miracle of gemini, I've bolted the binaries used for testing into this repo so you can make sure our basic assumptions work and dare to compare know uf2s to known elfs with CI/CD and github actions!

Run tests with `./scripts/run_tests.sh test`
> **NOTE:** This will install the latest ghidra in `./.ghidra` for you


# References
* Ghidra: https://github.com/NationalSecurityAgency/ghidra
* UF2 Specification: https://github.com/microsoft/uf2
