# Server Side Vulnerabilities : LEARNING PATH BY PORTSWIGGER

**Made By:** Haider Ali

---

## File Upload Vulnerabilities:
when a web server allows users to upload files to its filesystem without sufficiently validating things like their name, type, contents, or size.

In other cases, the website may attempt to check the file type by verifying properties that can be easily manipulated by an attacker using tools like Burp Proxy or Repeater.

the worst possible scenario is when a website allows you to upload server-side scripts, such as PHP, Java, or Python files, and is also configured to execute them as code.

### Web shell:
A web shell is a malicious script that enables an attacker to execute arbitrary commands on a remote web server simply by sending HTTP requests to the right endpoint.

solved the lab by uploading a php script that got the contents of the folder and echoed it on to the page....once uploaded I moved to the desired folder where images are stored using the url and the contents were displayed

