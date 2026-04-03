# Server Side Vulnerabilities : LEARNING PATH BY PORTSWIGGER

**Made By:** Haider Ali

---

## Server Side Request Forgery (SSRF):
a vulnerability that allows an attacker to cause the server side to make requests to an unintended location.

The attacker might cause the server to make a connection to internal-only services within the organization's infrastructure. In other cases, they may be able to force the server to connect to arbitrary external systems.

### Attacks against the server:

the application is forced to make an HTTP request back to the server hosting it.

involves supplying a url with ip pointing to local host such as 127.0.0.1

While using a shopping application, if we want to check whether item is in stock , the application would send a post request to the relevent API

**Example:**

**stockApi=http://stock.weliketoshop.net:8080/product/stock/check%3FproductId%3D6%26storeId%3D1**

we can edit this API url and make it look like 

**stockApi=http://localhost/admin**

allows us to access admin page with authorized access since the request comes from a trusted local authorized machine.

WHY does this happen ??

-> The access control check might be implemented in a diff component. 

-> application might allow admin access assuming only a fully trusted user would come from the server. Helps if admin forgets creds.

-> admin interface might be on an entirely diff port not reachable directly by users.

solved the SSRF lab by editing the api url in html to localhost/admin/delete?username=carlos

### Attacks against other backend systems:

In some cases, the application server is able to interact with back-end systems that are not directly reachable by users. These systems often have non-routable private IP addresses.

imagine there is an administrative interface at the back-end URL https://192.168.0.68/admin

we can edit the api url to 
**stockApi=http://192.168.0.68/admin**
