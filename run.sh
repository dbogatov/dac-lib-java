#!/usr/bin/env bash

DIRS="main/java"

rm -rf obj/*

javac -d obj -cp "./lib/*" src/$DIRS/*.java test/$DIRS/*.java

cd obj
java -cp ".:../lib/*" org.junit.runner.JUnitCore main.java.CredentialsTest main.java.GrothTest
