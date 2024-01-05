This program scans the opencanary log file for changes. When a change occurs, it graps the source IP in the log and creates a new address in the Fortigate. 
It then adds the address to the address group PYTHON_GROUP. If PYTHON_GROUP does not exist, the program will prompt the user to create it. 
However, in order for blocking to occur, the PYTHON_GROUP needs to be added to relevant block rules. 
I recommend running the program to create PYTHON_GROUP, and then adding the PYTHON_GROUP to the block rules manually.
(NOTE that PYTHON_GROUP will initally include a "throwaway" APIPA address, since groups cannot be empty in the Fortigate.)

You will also need to edit the "config values here" section of the code to include your firewall ip, port, and VDOM.
