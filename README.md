# Collect-ADObjects

A script to collect Active Directory Objects

![image](https://github.com/user-attachments/assets/a172dc23-ce96-48ff-b4a5-339800ffdb3c)


## Usage

Load the script first

```
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Collect-ADObjects/main/Collect-ADObjects.ps1')
```

Collect everything

```
Collect-ADObjects
```

Or pre-defined objects categories: Users, Computers, Groups, GPOs, DomainControllers, OUs, Printers, DomainPolicy, OtherPolicies, rIDManagers, Else
```
Collect-ADObjects -Collect Users
```
```
Collect-ADObjects -Collect Users,Computers,Groups
```

You can also specify -Enabled or -Disabled for the objects you want to collect

```
Collect-ADObjects -Collect Users -Enabled
```
```
Collect-ADObjects -Collect Users -Disabled
```

You can define the properties that you want to collect for the objects

```
Collect-ADObjects -Collect Users -Enabled -Property samaccountname
```
```
Collect-ADObjects -Collect Users -Enabled -Property samaccountname,memberof
```

Use the -Convert switch to convert the objectsid,pwdlastset,lastlogon,lastlogontimestamp,badpasswordtime properties to a readable format

```
Collect-ADObjects -Convert
```
```
Collect-ADObjects -Convert -Property pwdlastset,lastlogon,lastlogontimestamp,badpasswordtime,objectsid,samaccountname
```

You can specify a domain, and a DC to query

```
Collect-ADObjects -Collect Users -Enabled -Domain domain.local -Server DC.domain.local
```

You can collect a specific Identities as follows

```
Collect-ADObjects -Identity Administrator
```
```
Collect-ADObjects -Identity Administrator -Property samaccountname,memberof
```

Finally you can use LDAP and build your query

```
Collect-ADObjects -LDAP "objectClass=msDS-GroupManagedServiceAccount"
```
