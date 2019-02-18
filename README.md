# IDADatatrak
Binary loader and helper script for IDA 7.

This script loads Datatrak firmware binaries (joined form) into IDA, giving IDA some hints based on simple analysis of the binary.

The Helper script scans through the binary to find control structures and optimisations the Datatrak compiler (believed to be the HP 68000 C compiler).

## Installation

  - Copy idadtrak.py into IDA's loaders/ directory.
  - Copy idadtrak\_helper.py into a convenient directory.

## Usage

  - Load the firmware binary into IDA via the File -> Open option.
  - When asked to select the type of file, select "Datatrak".
  - After IDA has finished analysing the binary, select File -> Script File and run the Helper script.

