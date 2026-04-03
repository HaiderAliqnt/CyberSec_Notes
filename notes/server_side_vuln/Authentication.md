# Server Side Vulnerabilities : LEARNING PATH BY PORTSWIGGER

**Made By:** Haider Ali

---

## Authentication : 
verification of whether you are really who you say you are. 

Authentication vulnerablities allow acces to sensitive data and functionality.

### Brute Force attacks:
when an attacker uses a system of trial and error to guess valid user credentials. Typically automated and contains common usernames and passwords.

#### Username Emuration:
when attacker is able to observe changes in website behaviour to determine if username is valid or not.

### Bypassing 2FA
If the user is first prompted to enter a password, and then prompted to enter a verification code on a separate page, the user is effectively in a "logged in" state before they have entered the verification code. In this case, it is worth testing to see if you can directly skip to "logged-in only" pages after completing the first authentication step.

solved the lab by entering creds , entering the logged in state then...just clicking at the account tab since there was no check preventing access.

