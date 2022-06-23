# Insecure Function Finder

## General Information
- Author: Corey Hartman
- Language: Java 17
- Description: A Ghidra plugin to automatically find known insecure functions and will create a bookmark to quickly traverse to that location for review.
- Currently woks for the following functions: atoi, atol, atoll, exec, gets, memcpy, printf, sprintf, strcat, strcpy, strlen, strncpy, system, vsprintf

## Installation/Compilation
- Requires Ghidra
- Just place this script in your Ghidra plugins folder, which can be created by selecting "Manage Script Directories" in Ghidras Script Manager.
- Note: This was tested on Ghidra 10.4.1, older versions may not work as intended.

## Utilization
1. Perform analysis with Ghidra.
2. Open Ghidra's Script Manager.
3. Double Click InsecureFunctionFinder.java
4. Open Bookmarks to review discovered insecure functions.

