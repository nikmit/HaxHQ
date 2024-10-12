--
-- PostgreSQL database dump
--

-- Dumped from database version 11.7 (Debian 11.7-0+deb10u1)
-- Dumped by pg_dump version 11.7 (Debian 11.7-0+deb10u1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Data for Name: issues; Type: TABLE DATA; Schema: public; Owner: flask
--

COPY public.issues (id, name, title, severity, source, ignore, severity_mod) FROM stdin;
321	Browsable Web Directories	Browsable Web Directories	2	\N	f	0
322	CGI Generic XSS	CGI Generic XSS (quick test)	2	\N	f	0
78	SNMP Agent Default Community Name (public)	SNMP Agent Default Community Name (public)	3	\N	f	0
83	IPMI v2.0 Password Hash Disclosure	IPMI v2.0 Password Hash Disclosure	2	\N	f	0
71	Unsupported Windows OS (remote)	Unsupported Windows OS (remote)	4	\N	f	0
2	SSH Protocol Version 1 Session Key Retrieval	SSH Protocol Version 1 Session Key Retrieval	3	\N	f	0
74	iSCSI Unauthenticated Target Detection	iSCSI Unauthenticated Target Detection	3	\N	f	0
180	MTA Open Mail Relaying Allowed	MTA Open Mail Relaying Allowed	3	\N	f	0
186	Oracle TNS Listener Remote Poisoning	Oracle TNS Listener Remote Poisoning	3	\N	f	0
182	Redis Server Unprotected by Password Authentication	Redis Server Unprotected by Password Authentication	3	\N	f	0
99	PHP Unsupported Version Detection	PHP Unsupported Version Detection	4	\N	f	0
40	Unix Operating System Unsupported Version Detection	Unix Operating System Unsupported Version Detection	3	\N	f	0
43	SSL Version 2 and 3 Protocol Detection	SSL Version 2 and 3 Protocol Detection	3	\N	f	0
206	Oracle Database Unsupported Version Detection	Oracle Database Unsupported Version Detection	3	\N	f	0
205	CGI Generic SQL Injection	CGI Generic SQL Injection	3	\N	f	0
82	iLO 4 < 2.60 / iLO 5 < 1.30 Multiple Vulnerabilities	iLO 4 < 2.60 / iLO 5 < 1.30 Multiple Vulnerabilities	3	\N	f	0
207	Microsoft RDP Remote Code Execution (BlueKeep)	Microsoft RDP RCE (CVE-2019-0708) (BlueKeep) (uncredentialed check)	4	\N	f	0
208	HP iLO 4 Remote Code Execution Vulnerability	iLO 4 < 2.53 Remote Code Execution Vulnerability	4	\N	f	0
209	Dropbear SSH Server < 2016.72 Multiple Vulnerabilities	Dropbear SSH Server < 2016.72 Multiple Vulnerabilities	4	\N	f	0
210	phpMyAdmin 4.7.7 < 4.9.2 SQLi	phpMyAdmin 4.7.7 < 4.9.2 SQLi (PMASA-2019-5)	3	\N	f	0
215	HP iLO Remote Code Execution	HP iLO 4 <= 2.52 RCE	4	\N	f	0
216	SolarWinds Dameware Mini Remote Control Unauthenticated RCE	SolarWinds Dameware Mini Remote Control Unauthenticated RCE	4	\N	f	0
217	Microsoft IIS 6.0 Unsupported Version Detection	Microsoft IIS 6.0 Unsupported Version Detection	4	\N	f	0
218	Microsoft Windows XP Unsupported Installation Detection	Microsoft Windows XP Unsupported Installation Detection	4	\N	f	0
219	NFS Exported Share Information Disclosure	NFS Exported Share Information Disclosure	4	\N	f	0
220	HP Data Protector Arbitrary Command Execution	HP Data Protector 'EXEC_INTEGUTIL' Arbitrary Command Execution	4	\N	f	0
221	IBM WebSphere Java Object Deserialization RCE	IBM WebSphere Java Object Deserialization RCE	4	\N	f	0
222	HP iLO Multiple Vulnerabilities	iLO 4 < 2.70 / iLO 5 < 1.40a Multiple Vulnerabilities	3	\N	f	0
111	Flexera FlexNet Publisher < 11.16.2 Multiple Vulnerabilities	Flexera FlexNet Publisher < 11.16.2 Multiple Vulnerabilities	3	\N	f	0
75	Microsoft Windows SMBv1 Multiple Vulnerabilities	Microsoft Windows SMBv1 Multiple Vulnerabilities	3	\N	f	0
223	VNC Server Unauthenticated Access	VNC Server Unauthenticated Access	3	\N	f	0
224	rsh Service Detection	rsh Service Detection	3	\N	f	0
225	Dell iDRAC Products Multiple Vulnerabilities	Dell iDRAC Products Multiple Vulnerabilities (Mar 2018)	3	\N	f	0
226	Java JMX Agent Insecure Configuration	Java JMX Agent Insecure Configuration	3	\N	f	0
227	PostgreSQL Default Unpassworded Account	PostgreSQL Default Unpassworded Account	3	\N	f	0
228	rlogin Service Detection	rlogin Service Detection	3	\N	f	0
229	Blind SQL Injection	Blind SQL Injection	2	\N	f	0
230	l2tpd < 0.68 Multiple Vulnerabilities	l2tpd < 0.68 Multiple Vulnerabilities	3	\N	f	0
231	PHP Remote Code Execution Vulnerability.	PHP < 7.1.33 / 7.2.x < 7.2.24 / 7.3.x < 7.3.11 Remote Code Execution Vulnerability.	3	\N	f	0
232	VMware ESX / ESXi Unsupported Version Detection	VMware ESX / ESXi Unsupported Version Detection	4	\N	f	0
98	Microsoft Windows Server 2003 Unsupported Installation Detection	Microsoft Windows Server 2003 Unsupported Installation Detection	4	\N	f	0
233	MS14-066: Vulnerability in Schannel Could Allow Remote Code Execution	MS14-066: Vulnerability in Schannel Could Allow Remote Code Execution (2992611) (uncredentialed check)	4	\N	f	0
234	PHP 5.6.x < 5.6.27 Multiple Vulnerabilities	PHP 5.6.x < 5.6.27 Multiple Vulnerabilities	4	\N	f	0
236	Windows Deployment Services TFTP Server Remote Code Execution Vulnerability	Windows Deployment Services TFTP Server Remote Code Execution Vulnerability	4	\N	f	0
237	OpenSSL Unsupported	OpenSSL Unsupported	4	\N	f	0
238	Web Server Directory Traversal Arbitrary File Access	Web Server Directory Traversal Arbitrary File Access	4	\N	f	0
239	Portable SDK for UPnP Devices (libupnp) < 1.6.18 Multiple Stack-based Buffer Overflows RCE	Portable SDK for UPnP Devices (libupnp) < 1.6.18 Multiple Stack-based Buffer Overflows RCE	4	\N	f	0
240	AXIS Multiple Vulnerabilities (ACV-128401)	AXIS Multiple Vulnerabilities (ACV-128401)	4	\N	f	0
241	AD Review: Kerberos password is not regularly changed	Last change of the Kerberos password: 1530 day(s) ago	4	\N	f	0
242	AD Review: Account(s) with SID History matching the domain	Account(s) with SID History matching the domain = 3	2	\N	f	0
243	VMware vCenter Server NFC Protocol Code Execution	VMware vCenter Server NFC Protocol Code Execution (VMSA-2013-0003)	3	\N	f	0
244	Apple AirPort Base Station Authentication Credential Encryption Weakness	Apple AirPort Base Station Authentication Credential Encryption Weakness	3	\N	f	0
245	MS17-010: Security Update for Microsoft Windows SMB Server (ETERNALBLUE) (WannaCry)	MS17-010: Security Update for Microsoft Windows SMB Server (4013389) (ETERNALBLUE) (ETERNALCHAMPION) (ETERNALROMANCE) (ETERNALSYNERGY) (WannaCry) (EternalRocks) (Petya) (uncredentialed check)	4	\N	f	0
246	Pivotal Software Redis LUA Multiple Vulnerabilities	Pivotal Software Redis LUA < 3.2.12 / 4.0.x < 4.0.10 / 5.0 < 5.0rc2 Multiple Vulnerabilities	3	\N	f	0
247	Unsupported Web Server Detection	Unsupported Web Server Detection	3	\N	f	0
248	Cisco Wireless LAN Controller Secure Shell (SSH) Denial of Service Vulnerability (cisco-sa-20191016-wlc-ssh-dos)	Cisco Wireless LAN Controller Secure Shell (SSH) Denial of Service Vulnerability (cisco-sa-20191016-wlc-ssh-dos)	3	\N	f	0
249	PHP CGI Query String Code Execution	PHP < 5.3.12 / 5.4.2 CGI Query String Code Execution	3	\N	f	0
250	Web Server HTTP Dangerous Method Detection	Web Server HTTP Dangerous Method Detection	3	\N	f	0
251	AD Review: unknown domain(s) used in SIDHistory	4 unknown domain(s) used in SIDHistory	2	\N	f	0
252	AD Review: More than 30% of admins are inactive	More than 30% of admins are inactive: 44%	2	\N	f	0
253	AD Review: Suspicious admin activities detected	Suspicious admin activities detected on 34 user(s)	2	\N	f	0
261	AD Review: SMBv1 activated on DC	SMB v1 activated on 6 DC	3	\N	f	0
263	AD Review: At least one member of an admin group is vulnerable to the kerberoast attack.	At least one member of an admin group is vulnerable to the kerberoast attack.	3	\N	f	0
271	Authentication Page Without Ratelimiting	Authentication Page Without Ratelimiting	0	\N	f	0
272	SIP Connections With World Access	SIP Service World Accessible	0	\N	f	0
281	AD Review: Last change of the Kerberos password: 3541 day(s) ago	Last change of the Kerberos password: 3541 day(s) ago	4	\N	f	0
282	AD Review: More than 30% of admins are inactive: 34%	More than 30% of admins are inactive: 34%	2	\N	f	0
283	AD Review: Number of password(s) found in GPO: 2	Number of password(s) found in GPO: 2	3	\N	f	0
292	Exim < 4.22 smtp_in.c HELO/EHLO Remote Overflow	Exim < 4.22 smtp_in.c HELO/EHLO Remote Overflow	3	\N	f	0
293	phpMyAdmin prior to 4.8.6 SQLi vulnerablity (PMASA-2019-3)	phpMyAdmin prior to 4.8.6 SQLi vulnerablity (PMASA-2019-3)	2	\N	f	0
294	PHP 5.5.x < 5.5.38 Multiple Vulnerabilities (httpoxy)	PHP 5.5.x < 5.5.38 Multiple Vulnerabilities (httpoxy)	3	\N	f	0
295	Out-of-date Version (Tomcat)	Out-of-date Version (Tomcat)	1	\N	f	0
296	Cross-site Scripting	Cross-site Scripting	3	\N	f	0
297	Session Cookie Not Marked as Secure	Session Cookie Not Marked as Secure	3	\N	f	0
304	Intel Management Engine Authentication Bypass (INTEL-SA-00075)	Intel Management Engine Authentication Bypass (INTEL-SA-00075) (remote check)	4	\N	f	0
305	Apache mod_proxy Content-Length Overflow	Apache mod_proxy Content-Length Overflow	4	\N	f	0
306	PHP Multiple Vulnerabilities	PHP 7.0.x < 7.0.12 Multiple Vulnerabilities	4	\N	f	0
307	Adobe ColdFusion Unsupported Version	Adobe ColdFusion Unsupported Version Detection	4	\N	f	0
308	Novell iManager Multiple Vulnerabilities	Novell iManager < 2.7.6 Patch 1 Multiple Vulnerabilities	3	\N	f	0
309	Oracle WebLogic Unsupported Version	Oracle WebLogic Unsupported Version Detection	4	\N	f	0
310	SunSSH CBC Plaintext Disclosure	SunSSH < 1.1.1 / 1.3 CBC Plaintext Disclosure	3	\N	f	0
311	Symantec pcAnywhere awhost32 Remote Code Execution	Symantec pcAnywhere awhost32 Remote Code Execution	4	\N	f	0
312	Netatalk OpenSession Remote Code Execution	Netatalk OpenSession Remote Code Execution	4	\N	f	0
313	NETGEAR Multiple Model PHP Remote Command Injection	NETGEAR Multiple Model PHP Remote Command Injection	4	\N	f	0
314	Apache Multiple Vulnerabilities	Apache 2.2.x < 2.2.34 Multiple Vulnerabilities	3	\N	f	0
315	Oracle WebLogic Server Deserialization RCE (CVE-2018-2628)	Oracle WebLogic Server Deserialization RCE (CVE-2018-2628)	3	\N	f	0
316	PHP Heap-Based Buffer Overflow Vulnerability.	PHP 7.3.x < 7.3.10 Heap-Based Buffer Overflow Vulnerability.	3	\N	f	0
317	Elasticsearch ESA-2015-06	Elasticsearch ESA-2015-06	3	\N	f	0
318	Apache < 1.3.27 Multiple Vulnerabilities (DoS, XSS)	Apache < 1.3.27 Multiple Vulnerabilities (DoS, XSS)	3	\N	f	0
319	CGI Generic SQL Injection	CGI Generic SQL Injection (2nd pass)	3	\N	f	0
320	ESXi 5.5 Multiple Vulnerabilities (VMSA-2017-0006)	ESXi 5.5 < Build 5230635 Multiple Vulnerabilities (VMSA-2017-0006) (remote check)	3	\N	f	0
\.


--
-- Data for Name: issue_description; Type: TABLE DATA; Schema: public; Owner: flask
--

COPY public.issue_description (id, issue_id, text, ignore, prefer) FROM stdin;
205	322	The remote web server hosts CGI scripts that fail to adequately sanitize request strings with malicious JavaScript.  By leveraging this issue, an attacker may be able to cause arbitrary HTML and script code to be executed in a user's browser within the security context of the affected site.\nThese XSS are likely to be 'non persistent' or 'reflected'.	t	f
206	322	The remote web server hosts CGI scripts that fail to adequately sanitize request strings with malicious JavaScript.  By leveraging this issue, an attacker may be able to cause arbitrary HTML and script code to be executed in a user's browser within the security context of the affected site.\r\nThese XSS are likely to be 'non persistent' or 'reflected'.	f	t
207	43	The remote service accepts connections encrypted using SSL 2.0 and/or SSL 3.0. These versions of SSL are affected by several cryptographic flaws, including:\n\n  - An insecure padding scheme with CBC ciphers.\n\n  - Insecure session renegotiation and resumption schemes.\n\nAn attacker can exploit these flaws to conduct man-in-the-middle attacks or to decrypt communications between the affected service and clients.\n\nAlthough SSL/TLS has a secure means for choosing the highest supported version of the protocol (so that these versions will be used only if the client or server support nothing better), many web browsers implement this in an unsafe way that allows an attacker to downgrade a connection (such as in POODLE). Therefore, it is recommended that these protocols be disabled entirely.\n\nNIST has determined that SSL 3.0 is no longer acceptable for secure communications. As of the date of enforcement found in PCI DSS v3.1, any version of SSL will not meet the PCI SSC's definition of 'strong cryptography'.	t	f
208	43	The remote service accepts connections encrypted using SSL 2.0 and/or SSL 3.0. These versions of SSL are affected by several cryptographic flaws, including:\r\n\r\n  - An insecure padding scheme with CBC ciphers.\r\n\r\n  - Insecure session renegotiation and resumption schemes.\r\n\r\nAn attacker can exploit these flaws to conduct man-in-the-middle attacks or to decrypt communications between the affected service and clients.\r\n\r\nAlthough SSL/TLS has a secure means for choosing the highest supported version of the protocol (so that these versions will be used only if the client or server support nothing better), many web browsers implement this in an unsafe way that allows an attacker to downgrade a connection (such as in POODLE). Therefore, it is recommended that these protocols be disabled entirely.\r\n\r\nNIST has determined that SSL 3.0 is no longer acceptable for secure communications. As of the date of enforcement found in PCI DSS v3.1, any version of SSL will not meet the PCI SSC's definition of 'strong cryptography'.	f	t
\.


--
-- Data for Name: issue_discoverability; Type: TABLE DATA; Schema: public; Owner: flask
--

COPY public.issue_discoverability (id, issue_id, text) FROM stdin;
27	82	High
72	180	Easy to discover but only internally or with border firewall permissions. (Discovered after tester source addresses were whitelisted.)
93	205	Medium: Requires intensive scanning or manual testing
99	215	High: Discovered using automated tools
101	216	High: Discovered usign automated tools
104	218	High: Discovered using automated tools
105	206	High: Discovered using automated tools
108	220	High: Discovered using automated tools
109	221	High: Discovered using automated tools
115	224	High: Discoverable using automated tools
118	226	High: Discoverable using automated tools
119	74	High: Discoverable using automated tools
120	182	Easily discovered but not visible externally without additional firewall permissions. (Discovered after tester source addresses were whitelisted.)
121	227	High: Discovered using automated tools
125	230	High: Discoverable using automated tools
127	232	High: Discoverable using automated tools
128	98	High: This was discovered via automated scanning tools.
130	233	High: Discovered using automated tools
131	234	High: Discovered using automated tools
132	236	High: Discovered using automated tools
137	239	High: Discovered using automated tools
139	241	High: Discovered using PingCastle, an automated and freely available tool
140	242	
141	243	High: Discovered using automated tools
142	244	High: discoverable using automated tools
143	2	High: This issue was discoverable via automated tools.
144	78	High: discoverable using automated tools
147	186	High: Easily discovered
151	248	High: Discoverable using automated tools
152	249	High: Discoverable using automated tools
153	250	High: Discovered using automated tools
154	251	
155	252	
156	253	
157	261	High: Discoverable using automated tools
158	263	High: Discovered using automated tools
160	271	
162	272	
163	281	High: Discovered using automated tools
164	282	
165	283	High: Discovered using automated tools
168	229	Medium: requires intensive scanning of the web application
169	292	High: Discovered using automated tools
170	43	High: Discovered using automated tools
171	247	High: Discoverable using automated tools
173	293	
174	294	High: The version of PHP is advertised in the X-Powered-By header.
175	295	
176	296	Medium: Requires intensive scanning of the web application with commercially available tools or much slower manual discovery
177	297	High: discoverable using automated tools or by opening a page in a modern browser and examining cookies using developer tools.
178	209	High: Discovered using automated tools
179	238	Medium: requires on-site access and relatively intensive scanning.
180	304	Medium: Discovered using automated tools; requires on-site access as both TCP/623 and TCP/16992 are not accessible to VPN authenticated users.
181	208	High: Discoverable using automated tools. Requires on-site access or VPN connection.
182	99	High: Discovered using automated tools. The PHP version is commonly advertised in the HTTP headers.
183	207	High: Discovered using automated tools
184	305	High: discoverable using automated tools
185	219	High: Discovered using automated tools
186	71	High: Discovered using automated tools
187	40	High: Discovered using automated tools
188	306	High: Discoverable using automated tools. The version of PHP is commonly advertised in HTTP headers
189	217	High: Discoverable using automated tools
190	307	High: Discoverable using automated tools
191	308	High: Discoverable using automated tools
192	309	High: discoverable using automated tools
193	240	High: Discoverable using automated tools
195	310	High: discoverable using automated tools
196	311	High: Discoverable using automated tools
197	237	High: discoverable using automated tools
198	312	High: Discovered using automated tools.
199	313	High: discovered using automated tool
200	83	High: discovered using automated tools
201	222	High: discoverable using automated tools
202	111	High: Discovered using automated tools
203	246	High: Discovered using automated tools
204	314	High: server version is readily advertised
205	231	High: the version of PHP is commonly advertised in HTTP headers
206	225	High: discoverable using automated tools
207	210	High: discoverable using automated tools
208	245	High: requires access to the on-site network.
209	315	High: Discovered using automated tools
210	316	High: PHP version is readily advertised in most cases
211	223	High: Discovered using automated tools
212	75	High: Discoverable using a multitude of freely available automated tools.
213	317	High: Discovered using automated tools
214	318	High: Advertised in HTTP header
215	228	High: Discoverable with automated tools
216	319	Medium: Requires intensive automated scanning of the web application
217	320	High: discovered using automated tools
\.


--
-- Data for Name: issue_exploitability; Type: TABLE DATA; Schema: public; Owner: flask
--

COPY public.issue_exploitability (id, issue_id, text) FROM stdin;
27	82	Unknown: Low if access to the iLO interface is restricted to admin VLANs only.
73	180	High: trivial to use this server as an outbound mail proxy
94	205	High: No exploits are required, easy to exploit
100	215	High: Exploits are available and trivial to use
102	216	Medium: No known exploits are available
105	218	High: Exploits are available
106	206	Unknown: Depends on the vulnerability and availability of exploits
109	220	High: Exploits available
110	221	Medium: Exploits are available.
116	224	High: No exploit required
119	226	High: no exploit required
120	74	High: No exploit required
121	182	High: anyone with network access can connect.
122	227	High: No exploit required
126	230	Medium: No known exploits are available
128	232	High: Exploits likely exist as the vulnerabilities are severe and affect a popular platform.
129	98	High: Exploits are available
131	233	High: Exploits are not widely available but likely exist
132	234	Medium: Depends on the availability of exploits and the server configuration
133	236	Medium: No known exploits are available but some likely exist.
138	239	Medium: Exploits are reportedly available but not easily accessible
140	241	Medium: The attacker would need to gain access to the hashed password of the krbtgt account.
141	242	
142	243	Medium: No known exploits are available at present
143	244	Medium: Requires access to transit traffic
144	2	Low: No known exploits are available
145	78	High: No exploit is required
148	186	High: Exploits are available
152	248	Medium: No known exploits are available
153	249	Medium: No exploit is required however not all configurations are exploitable
154	250	High: No exploit required
155	251	
156	252	
157	253	
158	261	Medium: In most cases requires the attacker to be directly connected to the local network.
159	263	Medium: While it is easy to retrieve the hashes for the privileged service accounts, further success will depend on the password strength. The tools used to crack these hashes are not trivial to use.
161	271	
163	272	
164	281	Medium: Requires access to the password or the password hash through other channels.
165	282	
166	283	High: no exploit required, the discovered credentials can be used directly
169	229	High: Multiple tools exist which can automate the otherwise relatively complex exploitation of Blind SQLi
170	292	Medium: No known exploits are publicly available, would require resources to develop or purchase one
171	43	Medium: The attacker needs access to the traffic and relatively high skills/resources
172	247	Unknown: Depends on the type of vulnerability present and the availability of exploits for it.
174	293	No known exploits are available
175	294	Medium: No exploits are publicly available; exploitation would require the resources to develop or purchase an exploit (if available).
176	295	
177	296	Medium: No exploit is required but the attacker needs to be able to get the user to visit a malicious URL, commnly through phishing emails.
178	297	Medium: To exploit this issue, the attacker needs to be able to intercept traffic. This generally requires local access to the web server or to the victim's network. Attackers need to understand layer 2 and have gained access to a system between the victim and the web server.
179	209	Medium: No known exploits are available. An attacker would need the resources to develop or purchase an exploit.
180	238	High: No exploit required, however the above request will be automatically sanitised by modern browser. An intercepting proxy like Burp is required.
181	304	High: Exploits are available. Would require on-site access or a suitable on-site proxy.
182	208	High: Exploits are publicly available and easy to execute
183	99	Unknown: Depends on the vulnerabilities present and the local configuration of the server.
184	207	High: Exploits are not yet widely available but very likely exist and will be published as the vulnerability is severe and the number of potentially exploitable hosts huge.
185	305	Medium: No known exploits are available. An attacker would need the resources to develop or purchase a working exploit.
186	219	High: Exploits are available
187	71	Unknown: Depends on the version of Windows and the specific vulnerabilities
188	40	Unknown: Depends on the presence and type of specific vulnerabilities.
189	306	Medium: No publicly available exploits exist, however some may be privately circulated. Additionally successful exploitation of PHP flaws commonly depends on the local server configuration.
190	217	High: where WebDav is enabled, multiple exploits exist. Aditionaly, DoS exploits are publicly available.
191	307	Medium: No publicly available exploits were found
192	308	Low: Session replay requires access to traffic. CSRF attack requires a legitimate user to click on a malicious link while logged on.
193	309	Unknown: Depends on the presence and type of vulnerabilities
194	240	High: Some exploits are available
196	310	High: Exploits are available
197	311	High: Exploits are available
198	237	Unknown: depends on the presence of exploitable vulnerabilities
199	312	High: Exploits are available
200	313	High: no exploit required
201	83	High: Exploits are available
202	222	Medium: No known exploits are available
203	111	Medium: No known exploits are available
204	246	High: Exploits are available
205	314	Medium: No known exploits are available
206	231	Medium: No exploits are publicly available. Successful exploitation depends on the local configuration.
207	225	Medium: No known exploits are available
208	210	Medium: depends on the local server configuration and the presence of the design.php file which contains the vulnerability.
209	245	High: Exploits are widely available and easy to use
210	315	High: Exploits are available, requires access to the on-site staff network.
211	316	Medium: No exploits are publicly available, an attacker would require the resources to develop or purchase an exploit.
212	223	Unknown: No exploit required. It was not possible to manually verify connectivity and level of access granted in the VNC session
213	75	High: No known exploits are available, however can be used without exploits for MiTM attacks locally
214	317	Medium: No known exploits are available
215	318	High: Various exploits are available but none have been tested or verified
216	228	Medium: No exploit needed but requires ability to intercept traffic.
217	319	High: No exploit required
218	320	Medium: No known exploits are available
\.


--
-- Data for Name: issue_impact; Type: TABLE DATA; Schema: public; Owner: flask
--

COPY public.issue_impact (id, issue_id, text) FROM stdin;
27	82	High
72	180	Medium: If used to send spam, the server’s IP address will likely be blacklisted, preventing it from sending legitimate mail.
93	205	High: Can cause authentication bypass, data theft or compromise and even full host compromise
99	215	High: With full administrative access to the iLO interface, an attacker can reboot and/or gain control of the host.
101	216	High: Full host compromise is likely if an exploit is developed or found.
104	218	High: Full compromise of the host
105	206	Unknown: Depends on the type of vulnerability and the sensitivity of the data stored in the database or elsewhere on the host 
108	220	High: Can lead to full host compromise
109	221	High: If exploited attacker would gain access to the host depending on the privileges of the account under which the WebSphere Server is running.
115	224	High: Depends on the privileges of the compromised account
118	226	High: can grant the attacker access to the host with the permissions of the user running JMX agent.
119	74	Unknown: Depends on the stored content
120	182	Unknown: Depends on the value of the public facing services utilising Redis and the type of data stored.
121	227	Unknown: depends on the privileges granted to the unprotected account and the data stored in the database
125	230	High: The announced vulnerabilities are severe and successful exploitation would lead to full host compromise.
127	232	High: Potential for compromising the physical server and all VMs hosted on it.
128	98	High: If the attacker is able to gain a foothold on the device, there is the high possibility of a full system compromise.
130	233	High: The vulnerability is severe and likely to lead to full host compromise
131	234	High: Successful exploitation would grant the attacker access with the privileges of the web server account.
132	236	High: Full host compromise
137	239	High: Successful exploitation would allow an attacker to execute arbitrary code with the privileges of the account running the service
139	241	High: Full domain compromise.
140	242	
141	243	High: If successfully exploited is likely to cause full host compromise
142	244	High: If administrator credentials are compromised the attacker will gain control of the device
143	2	High: If successful, the attacker can perform a MITM attack to steal login credentials.
144	78	Medium: Most likely result would be information disclosure about the network and hosts on it. This could help attackers to get further into the network. If SNMP write access is enabled the impact can be much more serious.
147	186	Unknown: depends on the data stored on this Oracle database.
151	248	Medium: Can be used to cause an outage of the wireless connectivity
152	249	High: If code execution is achieved, full host compromise is likely.
153	250	Unknown: Largely depends on the ability to execute written files
154	251	
155	252	
156	253	
157	261	High: Can be used to steal user credentials and if domain admin credentials are intercepted, compromise the domain.
158	263	High: If the plain text password is successfully obtained form the hash, the attacker would get domain admin rights.
160	271	
162	272	
163	281	High: Compromise of the AD domain.
164	282	
165	283	Unknown: Depends on the rights granted to the compromised accounts, and whether these are currently enabled.
168	229	High: Depending on the backend database, the database connection settings, and the operating system, an attacker can mount one or more of the following attacks successfully:\r\n- Reading, updating and deleting arbitrary data or tables from the database\r\n- Executing commands on the underlying operating system
169	292	High: buffer overflow vulnerabilities typically result in code execution on the server hosting the application.
170	43	Unknown: Depends on the value or sensitivity of the information transmitted
171	247	Unknown: Vulnerabilities in the web server itself commonly cause DoS conditions, authentication bypass or full compromise of the host.
173	293	
174	294	High: Some of the vulnerabilities announced are likely to lead to arbitrary code execution with the privileges of the web service account
175	295	
176	296	Impact: There are many different attacks that can be leveraged through the use of cross-site scripting, including:\r\n- Hijacking user's active session.\r\n- Mounting phishing attacks.\r\n- Intercepting data and performing man-in-the-middle attacks.
177	297	High: This cookie will be transmitted over a HTTP connection, therefore an attacker might intercept it and hijack a victim's session. If the attacker can carry out a man-in-the-middle attack, he/she can force the victim to make an HTTP request to your website in order to steal the cookie.
178	209	High: The vulnerabilities are serious and would fully compromise the host if successfully exploited.
179	238	High: If files containing hashed credentials are retrieved these can then be subjected to an offline brute force attack. Additionally, various configuration files can contain clear text passwords.
180	304	High: can lead to full host compromise.
181	208	High: Can lead to DoS or full host compromise.
182	99	Unknown: PHP vulnerabilities commonly lead to arbitrary code execution on the host with the privileges of the web service account.
183	207	High: Full host compromise.
184	305	High: Can lead to DoS or arbitrary code execution with the privileges of the account Apache is running as.
185	219	Unknown: Depends on the availability of 'write' access and the type of information exposed
186	71	Unknown: Likely to lead to full host compromise as exploits for old Windows vulnerabilities are widely available.
187	40	Unknown: Old Unix systems are commonly vulnerable to privilege escalation attacks and depending on the services installed may be remotely exploitable as well.
188	306	High: if successfully exploited, the attacker is likely to gain access to the host with the privileges of the account running the web service.
189	217	High: Denial of service or full host compromise.
190	307	Unknown: Depends on the vulnerability being exploited
191	308	High: if successfully exploited can grant the attacker authenticated access to the remote management functionality.
192	309	Unknown: Depends on the type of vulnerability exploited
193	240	High: Can lead to privacy issues with an attacker gaining access to footage. Additionally, could be configured to serve as a pivot point to grant an external attacker access to the local network.
195	310	High: If credentials or similar sensitive information is exposed can lead to full host compromise.
196	311	High: Full host compromise
197	237	Unknown: depends on the type of vulnerability exploited
198	312	High: arbitrary code execution with the privileges of the account the service is running as
199	313	High: full host compromise
200	83	Medium: Depends on the strength of passwords in use. Successful recovery of the plain text password can lead to full host compromise.
201	222	High: If arbitrary code execution is achieved full host compromise is likely.
202	111	Medium: the published vulnerabilities are likely to cause denial of service
203	246	High: Full host compromise is likely
204	314	Medium: Most of the vulnerabilities would cause denial of service if exploited, with the exception of the authentication bypass which can grant unauthorised access to content or web interface functionality.
205	231	High: if successfully exploited the attacker can execute arbitrary commands on the host with the privileges of the account the web service is running as.
206	225	High: likely to lead to full host compromise or denial of service
207	210	High: successful exploitation would grant access to database content with the privileges of the relevant account. Can lead to full host compromise in some cases.
208	245	High: Full host compromise, commonly used for ransomware attacks.
209	315	High: a successful attacker would gain access to the host with the privileges of the account WebLogic is running as.
210	316	High: A successful attacker could gain control of the host with the privileges of the web service account.
211	223	High: depends on the level of access gained
212	75	Medium: Can lead to information disclosure. Depending on the types of users using the service, could lead to the capture of user logins and a knock-on effect depending on the rights of those users within the domain.
213	317	High: Can lead to full host compromise
214	318	High: Could lead to code execution with the rights of the account Apache is running as.
215	228	High: A successful attacker could gain access to the host with the rights of the intercepted legitimate user.
216	319	High: Can lead to information disclosure, data loss or compromise and even execution of arbitrary commands on the host with the rights of the database user.
217	320	High: Can lead to compromise of the ESXi server through one of the hosted VMs. If all hosted VMs are administered by trusted personnel and contain no exploitable vulnerabilities impact is mitigated.
\.


--
-- Data for Name: issue_remediation; Type: TABLE DATA; Schema: public; Owner: flask
--

COPY public.issue_remediation (id, issue_id, text, ignore, prefer) FROM stdin;
229	43	Consult the application's documentation to disable SSL 2.0 and 3.0.\nUse TLS 1.1 (with approved cipher suites) or higher instead.	t	f
230	43	Consult the application's documentation to disable SSL 2.0 and 3.0.\r\nUse TLS 1.2 (with approved cipher suites) or higher instead.	f	t
\.


--
-- Name: issue_description_id_seq; Type: SEQUENCE SET; Schema: public; Owner: flask
--

SELECT pg_catalog.setval('public.issue_description_id_seq', 210, true);


--
-- Name: issue_discoverability_id_seq; Type: SEQUENCE SET; Schema: public; Owner: flask
--

SELECT pg_catalog.setval('public.issue_discoverability_id_seq', 218, true);


--
-- Name: issue_exploitability_id_seq; Type: SEQUENCE SET; Schema: public; Owner: flask
--

SELECT pg_catalog.setval('public.issue_exploitability_id_seq', 219, true);


--
-- Name: issue_impact_id_seq; Type: SEQUENCE SET; Schema: public; Owner: flask
--

SELECT pg_catalog.setval('public.issue_impact_id_seq', 218, true);


--
-- Name: issue_remediation_id_seq; Type: SEQUENCE SET; Schema: public; Owner: flask
--

SELECT pg_catalog.setval('public.issue_remediation_id_seq', 232, true);


--
-- Name: issues_id_seq; Type: SEQUENCE SET; Schema: public; Owner: flask
--

SELECT pg_catalog.setval('public.issues_id_seq', 1, false);


--
-- PostgreSQL database dump complete
--

