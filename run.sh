#!/bin/bash
# Compile
javac -cp ".:lib/*" *.java

# Run
java -cp ".:lib/*" Main
