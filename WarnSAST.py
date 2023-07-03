import sys
import os
import re
from datetime import datetime

"""
0-> C/C++ command injection
1-> Python command injection
2-> Java command injection
3-> C/C++ buffer
4-> Java deserialization
5-> Python deserialization
"""

vulnerable_function_com= [["system","popen", "execlp","execvp","ShellExecute","_wsystem"],["exec","eval", "execfile","input","compile","os.system","os.popen"],["Class.forName","Runtime.exec"]]
vulnerable_function_buf= ["gets","strcpy", "strcat","sprintf","scanf"]
vulnerable_function_ser= [["readObject"], ["pickle.load","pickle.loads"]]
vulnerable_function_buf[4] = vulnerable_function_buf[4] +".*%s"
vulnerable_reg = [[".*" + sub for sub in vulnerable_function_com[0]], [".*" + sub for sub in vulnerable_function_com[1]], [".*" + sub for sub in vulnerable_function_com[2]], [".*" + sub for sub in vulnerable_function_buf], [".*" + sub for sub in vulnerable_function_ser[0]], [".*" + sub for sub in vulnerable_function_ser[1]]]

def get_logname():
    """
    Calculates a filename for the log
    :return: a filename fot logging
    """
    now = datetime.now()
    dt_string = now.strftime("%d_%m_%Y_%H_%M_%S")
    filename="WarnSAST_log_"+dt_string+".txt"
    print(filename)
    return filename

def logger (logfilename:str , filename:str, line, vulnerability:str):
    """
    Log the found vulnerability in a file
    :param logfilename: file of the log
    :param filename: file where the vulnerability is found
    :param line: line where the vulnerability is found
    :param vulnerability: name of the vulnerability
    """
    if(not os.path.exists("LOGS")):
        os.mkdir("LOGS")
    logpath="LOGS/"+logfilename
    logfile = open(logpath, 'a')
    log= "FILE -> "+filename+" possibile "+vulnerability+" vulnerability in line: "+ str(line) +"\n"
    logfile.write(log);
    logfile.close()


def checker(filename: str ,logfilename: str=None):
    """
    Check the file for vulnerability and log them if a logfilename is provvided
    :param filename: file where search for vulnerability
    :param logfile: file where to write the log
    """
    file = open(filename,'r')
    Lines = file.readlines()
    count = 0
    type=0
    if (filename.endswith('.c') or (filename.endswith('.cpp'))):
        type=0
    if (filename.endswith('.py')):
        type=1
    if (filename.endswith('.java')):
        type=2

    for line in Lines:
        count += 1
        if (type == 0):
            for vulfun in vulnerable_reg[3]:
                if (re.match(vulfun, line) != None):
                    print("Possible buffer overrun vulnerability found in the file", filename, " line", count)
                    if logfilename != None:
                        logger(logfilename, filename, count, "buffer overrun")
        if (type == 1):
            for vulfun in vulnerable_reg[4]:
                if (re.match(vulfun, line) != None):
                    print("Possible deserialization of untrusted message vulnerability found in the file", filename, " line", count)
                    if logfilename != None:
                        logger(logfilename, filename, count, "deserialization of untrusted message")

        if (type == 2):
            for vulfun in vulnerable_reg[5]:
                if (re.match(vulfun, line) != None):
                    print("Possible deserialization of untrusted message vulnerability found in the file", filename, " line", count)
                    if logfilename != None:
                        logger(logfilename, filename, count, "deserialization of untrusted message")

        for vulfun in vulnerable_reg[type]:
            if(re.match(vulfun,line) != None):
                print("Possible command injection vulnerability found in the file", filename," line", count)
                if logfilename != None:
                    logger(logfilename,filename,count, "command injection")



def switch():
    """
    Runs the programs and select the mode to execute
    """
    if len(sys.argv)<3 or len(sys.argv)>4:
        print("To few argument, read the README.md file")
        return None

    if sys.argv[1]=="-f" or sys.argv[1]=="--file":
        print("File mode selected")
        if (len(sys.argv) == 4):
            if(sys.argv[3] == "-l" or sys.argv[3] == "--log"):
                logfile = get_logname()
                if(sys.argv[2].endswith('.c') or (sys.argv[2].endswith('.cpp')) or sys.argv[2].endswith('.py') or sys.argv[2].endswith('.java')):
                    print("Found", sys.argv[2])
                    checker(sys.argv[2], logfile)
            else:
                print("wrong argument, read the README.md file")
        else:
            if(sys.argv[2].endswith('.c') or (sys.argv[2].endswith('.cpp')) or sys.argv[2].endswith('.py') or sys.argv[2].endswith('.java')):
                print("Found", sys.argv[2])
                checker(sys.argv[2])


    if sys.argv[1]=="-d" or sys.argv[1]=="--directory":
        print("Directory mode selected")
        try:
            if (len(sys.argv) == 4):
                if (sys.argv[3] == "-l" or sys.argv[3] == "--log"):
                    logfile = get_logname()
                    files = os.listdir(sys.argv[2])
                    for file in files:
                        if(sys.argv[2].endswith('.c') or (sys.argv[2].endswith('.cpp')) or sys.argv[2].endswith('.py') or sys.argv[2].endswith('.java')):
                            print("Found: ",file)
                            if (sys.argv[2].endswith("/")):
                                sys.argv[2] = sys.argv[2][:-1]
                                print(sys.argv[2])
                            pathtofile=sys.argv[2]+"/"+file
                            checker(pathtofile,logfile)
                else:
                    print("wrong argument, read the README.md file")

            else:
                files = os.listdir(sys.argv[2])
                for file in files:
                    if(sys.argv[2].endswith('.c') or (sys.argv[2].endswith('.cpp')) or sys.argv[2].endswith('.py') or sys.argv[2].endswith('.java')):
                        print("Found: ", file)
                        pathtofile = sys.argv[2] + "/" + file
                        checker(pathtofile)

        except Exception as e:
            print(e)
            print("Invalid Directory")

#START MAIN -------------------------------------------------------------
switch()
#END MAIN ---------------------------------------------------------------
