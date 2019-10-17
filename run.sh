#!/usr/bin/env bash

set -e

# Ensure that the CWD is set to script's location
cd "${0%/*}"
CWD=$(pwd)

DIRS="app"

rm -rf obj/*

javac -d obj -cp "./lib/*" src/$DIRS/*.java test/$DIRS/*.java

cd obj
java -cp ".:../lib/*" org.junit.runner.JUnitCore $DIRS.CredentialsTest $DIRS.GrothTest
