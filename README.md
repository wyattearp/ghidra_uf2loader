# Overview 
Try to provide a slightly better than raw binary loader for UF2 files when loading them into Ghidra.

## Motivation
Have you ever come across a .UF2 file and thought "why the heck would I spend time cloning this other repo and then using a python script to convert it to a flat flash block for importing into Ghidra when I could spend time writing a loader?" ... well, then you're me and this is the result of 5 hours of interrupt driving development.

## Installation
You can either install from the zip if you trust me or you can build the code yourself. This has been "tested" as in "works for me" on Ghidra 10.0.1

## Building the Code
You'll need Eclipse, Ghidra, and a copy of the code:

1. Clone the project
1. Open the project in Eclipse
1. Connect to your Ghidra Instance in your Eclispe Settings (see their docs)
1. Clicke `Ghidra Dev -> Export --> Ghidra Module Extension`
1. Take that zip file and load it into Ghidra

# Refernces
* Ghidra: https://github.com/NationalSecurityAgency/ghidra
* UF2 Specification: https://github.com/microsoft/uf2
