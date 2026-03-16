# Server Side Vulnerabilities : LEARNING PATH BY PORTSWIGGER

**Made By:** Haider Ali

---

## Path Traversal : 

also known as directory traversal ; allows attackers to access files and directories outside the intented scope of a web application. Involves path manipulation by using sequences like **../** (unix/linux) or **..\\** (windows) to navigate up the directory tree and then access known files such as config , passwords or source code.


### Example :

a platform loads images using this html
**<img src="/loadImage?filename=218.png">** 

so the URL takes a filename param 
the param is appended to the base directory **/var/www/images**
and the content is fetched from 
**/var/www/images/218.png**

an attacker can request this url to access /etc/passwd file 
by appending "../" and going to previous directory in the heirarchy till you reach the root and then move into /etc/passwd
**/var/www/images/../../../etc/passwd**
so the url looks like
**https://insecure-website.com/loadImage?filename=../../../etc/passwd**
equivalent attack on windows system would be
**https://insecure-website.com/loadImage?filename=..\..\..\windows\win.ini**


