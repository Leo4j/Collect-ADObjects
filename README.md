# Collect-ADObjects

A function to collect Active Directory Objects

## Usage

Load the function first

```
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Collect-ADObjects/main/Collect-ADObjects.ps1')
```

You can use the function to collect everything

```
Collect-ADObjects # collects everything
```

Or pre-defined objects categories: Users, Computers, Groups, GPOs, DomainControllers, OUs, Else, Printers, DomainPolicy, OtherPolicies, rIDManagers
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

You can specify a domain to collect for, and a DC to query

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
