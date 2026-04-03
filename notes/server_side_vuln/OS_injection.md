# Server Side Vulnerabilities : LEARNING PATH BY PORTSWIGGER

**Made By:** Haider Ali

---


## OS injection:
OS command injection is also known as shell injection. It allows an attacker to execute operating system (OS) commands on the server that is running an application, and typically fully compromise the application and its data.

a shopping application lets the user view whether an item is in stock in a particular store via this url

https://insecure-website.com/stockStatus?productID=381&storeID=29

For historical reasons, the functionality is implemented by calling out to a shell command with the product and store IDs as arguments:

stockreport.pl 381 29

command outputs the stock status for the specified item

The application implements no defenses against OS command injection, so an attacker can submit the following input to execute an arbitrary command:

**& echo aiwefwlguh &**
stockreport.pl & echo aiwefwlguh & 29

echo causes the string to be displayed in the output ...useful to test for types of OS injection

**&**acts as a shell command separator.

the output:
Error - productID was not provided
aiwefwlguh
29: command not found

injected command is executed and 29 not recognized since it was meant to be a param not a command. Error provided since params were not provided to the script

solved the lab by editing the value that the stock form sends to the backend script...since we can assume that value must be a param for the intended stock function
instead of "1" edit it to "1 & whoami" to get the answer. 
