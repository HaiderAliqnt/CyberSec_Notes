# Server Side Vulnerabilities : LEARNING PATH BY PORTSWIGGER

**Made By:** Haider Ali

---

## Access Control

Constraints in systems on who or what is authorized to perform certain actions or access certain resources. 

**Authentication** : confirms user is who they say they are
**Session Management** : identifies which subsequent http requests are being made by that same user
**Access Control** : determines whether user is allowed to carry out the action they are attempting to perform.

Broken controls are common and are a critical security vulnerability.
Designed by humans so potential of error is high

### Vertical privilege Escalation
When a user can gain access to functionality that they are not permitted to access. Example includes a non admin user can gain access to an admin page where accounts can be deleted.

It arises when an application doesnot enforce any protection for sensitive functionality. Admin functions are kept away from the pages intented for users but users can access the admin page by browsing to the admin URL.

**https://insecure-website.com/admin**

In some cases, the administrative URL might be disclosed in other locations, such as the robots.txt file:
**https://insecure-website.com/robots.txt**
an attacker may be able to use a word list to brute force the location.

lab solved by first accessing robots.txt , then accessing the url written for admin there

**Security by Obscurity** :
Sensitive functionality is concealed by giving it a less predictable url. 

Not directly guessable but the source code in JS can leak the url 

<script>
	var isAdmin = false;
	if (isAdmin) {
		...
		var adminPanelTag = document.createElement('a');
		adminPanelTag.setAttribute('href', 'https://insecure-website.com/administrator-panel-yb556');
		adminPanelTag.innerText = 'Admin panel';
		...
	}
</script>

This script adds a link to the user's UI if they are an admin user. However, the script containing the URL is visible to all users regardless of their role.

CTRL+U to view the source code

lab solved by viewing source code and looking at isAdmin function

#### Parameter-based methods

Some applications determine user's access rights or role at login and store the info. 

**https://insecure-website.com/login/home.jsp?admin=true**
**https://insecure-website.com/login/home.jsp?role=1**

insecure approach because the user can modify the value and gain unauthorized access. 

lab solved by modifying cookie on login to set admin to true. 


### Horizontal Privelege Escalation 

When a user can gain access to resources belonging to another user.

uses similiar techniques as vertical privilege 

For example, a user might access their own account page using the following URL:
**https://insecure-website.com/myaccount?id=123**
if we modify the id param we can access another user

This is an example of an insecure direct object reference **(IDOR) vulnerability**. This type of vulnerability arises where user-controller parameter values are used to access resources or functions directly.

If an application uses unpredictable values instead of incrementing numbers then the GUIDs need to be disclosed some other way by looking at places where the user is referenced. 

lab solved by searching for user in the blog posts...then looking at the source code to fetch their GUID then paste it in the login URL with ID param

a horizontal privilege can turn into a vertical case by gaining access to an account with more auth rights.

solved the lab by first loggin in as wiener 
then changin id param to administrator and
extracting the password from hidden field.
Then used that id password to login as admin and access the panel to delete carlos.