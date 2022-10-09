# SAST TOOL FOR SIMPLE VULNERABILITIES

------------------------------------------------

 ## Description
This program aims to identify the use of unsafe library function that can cause the 
Command injection in C/C++/Python/Java files and buffer over run in C/C++


## Usage
There are 2 mode of execution:
* Single file mode: checks only one .c/.cpp/.py/.java file, 
to use it you need to use "-f" or "--file" followed by a filepath/filename.c
* File directory mode: checks all the .c/.cpp/.py/.java file in a directory, 
to use it you need to use "-d" or "--directory" followed by the directorypath

also after these 2 can be added "-l" or "--log" 
to store the log of the execution in a file called WarnSAST_log_DD_MM_YYYY_HH__MM_SS.txt 
located in the folder LOGS