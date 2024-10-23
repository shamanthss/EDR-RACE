# Install Osquery
```sh
https://pkg.osquery.io/windows/osquery-5.13.1.msi
```
&nbsp;
# Invoke Osquery

```sh
& 'C:\Program Files\osquery\osqueryi.exe'
```
&nbsp;
# Osquery Threat Hunting Basics (Windows)

## 1. Logged Users 
Query to find who are the logged in users in the system 

### Query:
```sql
select * from logged_in_users ;
```
&nbsp;
## 2. Previous Logged Users 
Previous logins

### Query:
```sql
select * from last ;
```
&nbsp;
## 3. Previous Logged Users 
Find all the listening ports to check if there is any backdoor to the system. If there is any open port that you have not configured then you might need to examine the process that opened this port.

### Query:
```sql
select * from listening_ports;
```
&nbsp;
## 4. Process Image 
Find the top 10 largest processes by resident memory size.

### Query
```sql
select pid, name, uid, resident_size from processes order by resident_size desc limit 10;
```
&nbsp;
## 5. Running Process 
Find all the running processes.

### Query
```sql
select * from processes;
```
&nbsp;
## 6. Find Running Processes
Find all the running svchost.exe processes.

### Query
```sql
SELECT * FROM processes WHERE name = "svchost.exe" 
```

---
&nbsp;
# Osquery Advanced Threat Hunting (Windows)
&nbsp;
## 7. Process Mapping
Map all processes to listing ports they currently have open.

### Query
```sql
SELECT DISTINCT process.name, listening.port, listening.address, process.pid FROM processes AS process JOIN listening_ports AS listening ON process.pid = listening.pid;
```
&nbsp;
## 8. Process Mapping
Find all processes with no EXE backing it

### Query
```sql
SELECT name, path, pid FROM processes WHERE on_disk = 0;
```
---
&nbsp;
# Uncovering Persistence with Osquery (Windows)

## 9. Create Account - T1136
Any recent, abnormal local users?
The two WHERE clauses help filter down results

### Query
```sql
SELECT uid,username,shell,directory FROM users
 WHERE type = ‘local’; → Windows Domain Joined systems
 WHERE shell NOT LIKE ‘%/bin/false’; 
```
&nbsp;
## 10. Create Account - T1136
What users have administrative privileges?
Default Admin group IDs:
Windows [Administrators] = 544
MacOS [admin] = 80
Ubuntu Linux [sudo, root] =27,0

### Query
```sql
SELECT users.uid,users.username,users.shell FROM user_groups
 INNER JOIN users ON user_groups.uid = users.uid
 WHERE user_groups.gid = @groupid;
```
&nbsp;
## 11. New Service - T1050
Any abnormal services?
Only displays services that are set to auto start, and filters out
legit svchost services.

### Query
```sql
SELECT name,display_name,user_account,path FROM services
 WHERE start_type = ‘AUTO_START’
 AND path NOT LIKE ‘C:\Windows\system32\svchost.exe -k %’;
```
&nbsp;
## 12. New Service - T1050
Any abnormal services?
Only displays services that are set to auto start, and filters out
legit svchost services.

### Query
```sql
SELECT hidden,name,action
 FROM scheduled_tasks WHERE enabled = 1;
```
&nbsp;
## 13. User Login/Startup Items - T1165
Any startup items?
Lots of stuff can be filtered out. for eg:
Windows = desktop.ini for each user profile

### Query
```sql
SELECT name,path,source,status,username
 FROM startup_items;
```
&nbsp;
## 14. Browser Extensions - T1176
Any abnormal extensions?
Joined with the users table, to get the username;
Useful to filter for all extensions for a particular user

### Query
```sql
SELECT users.username,chrome_extensions.name,
 chrome_extensions.identifier,chrome_extensions.path
 FROM users CROSS JOIN chrome_extensions USING (uid);
```
&nbsp;
## 15. Browser Extensions - T1176
Any abnormal extension identifiers?
Fuzzy search for extension name and compare against known
good identifier/s

### Query
```sql
SELECT users.username,chrome_extensions.name FROM users
CROSS JOIN chrome_extensions USING (uid) WHERE name LIKE
‘%lastpass%’ AND identifier <> ‘hdokiejnpimakedhajhdlcegeplioahd’;
```
&nbsp;
## 16. Application Shimming - T1138
Any suspicious entries in the AppCompat shims?
Web searching the SDB ID can provide lots of c

### Query
```sql
SELECT executable,path,description,sdb_id
 FROM appcompat_shims;
``` 
