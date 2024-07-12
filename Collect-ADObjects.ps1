function Collect-ADObjects {

    <#

    .SYNOPSIS
    Collect-ADObjects | Author: Rob LP (@L3o4j)
    https://github.com/Leo4j/Collect-ADObjects

    .DESCRIPTION
    Collect Active Directory Objects

    #>

    param (
        [string]$Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name,
        [string]$Server = $null,
        [int]$numOfThreads = 4,
		[Parameter(Mandatory = $false)]
        [ValidateSet("Users", "Computers", "Groups", "GPOs", "DomainControllers", "OUs", "Else", "Printers", "DomainPolicy", "OtherPolicies", "rIDManagers")]
        [string[]]$Collect = @("Users", "Computers", "Groups", "GPOs", "DomainControllers", "OUs", "Else", "Printers", "DomainPolicy", "OtherPolicies", "rIDManagers"),
		[string[]]$Property,
		[switch]$Enabled,
        [switch]$Disabled,
		[string]$Identity,
		[string]$LDAP,
		[switch]$Convert
    )
	
	$root = if ($Server) {
        "LDAP://$Server"
    } else {
        "LDAP://$Domain"
    }
	
	$rootDirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry($root)
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($rootDirectoryEntry)
	
	# Construct the LDAP filter based on the -Collect parameter
    $filters = @()
	if ($Identity) {
        $filters += "(samAccountName=$Identity)"
    }
	elseif ($LDAP) {
        $filters += "($LDAP)"
    }
	else{
		foreach ($item in $Collect) {
			switch ($item) {
				"Users" { 
					$userFilter = "(objectCategory=person)"
					if ($Enabled) {
						$userFilter = "(&" + $userFilter + "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
					} elseif ($Disabled) {
						$userFilter = "(&" + $userFilter + "(userAccountControl:1.2.840.113556.1.4.803:=2))"
					}
					$filters += $userFilter
				}
				"Computers" { 
					$computerFilter = "(objectCategory=computer)"
					if ($Enabled) {
						$computerFilter = "(&" + $computerFilter + "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
					} elseif ($Disabled) {
						$computerFilter = "(&" + $computerFilter + "(userAccountControl:1.2.840.113556.1.4.803:=2))"
					}
					$filters += $computerFilter
				}
				"Groups" { $filters += "(objectCategory=group)" }
				"DomainControllers" { $filters += "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))" }
				"OUs" { $filters += "(objectCategory=organizationalUnit)" }
				"GPOs" { $filters += "(objectClass=groupPolicyContainer)" }
				"Else" { $filters += "(&(!(objectCategory=person))(!(objectCategory=computer))(!(objectCategory=group))(!(objectCategory=organizationalUnit))(!(objectClass=groupPolicyContainer)))" }
				"Printers" { $filters += "(objectCategory=printQueue)" }
                "DomainPolicy" { $filters += "(objectClass=domainDNS)" }
                "OtherPolicies" { $filters += "(cn=Policies*)" }
				"rIDManagers" { $filters += "(objectClass=rIDManager)" }
			}
		}
	}
    # Combine the filters with an OR if multiple categories are specified
    $searcher.Filter = if ($filters.Count -gt 1) { "(|" + ($filters -join "") + ")" } else { $filters[0] }
	
    # Specify the properties to load if provided
    if ($Property) {
        $Property += "domain"  # Ensure 'domain' is always collected
        foreach ($prop in $Property) {
            $null = $searcher.PropertiesToLoad.Add($prop)
        }
    }
	
	$searcher.PageSize = 1000
	$searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
    $results = $searcher.FindAll()

    [System.Collections.Generic.List[PSObject]]$records = New-Object 'System.Collections.Generic.List[PSObject]'
    foreach ($result in $results) {
        $properties = @{}
        foreach ($prop in $result.Properties.PropertyNames) {
            if ($result.Properties[$prop].Count -gt 1) {
                $properties[$prop] = $result.Properties[$prop]
            } else {
                $properties[$prop] = $result.Properties[$prop][0]
            }
        }
		
		# Convert properties if the -Convert switch is specified
        if ($Convert) {
            if ($properties.ContainsKey('objectsid')) {
                $properties['objectsid'] = GetSID-FromBytes -sidBytes $properties['objectsid']
            }
            $timestampProperties = @('pwdlastset', 'lastlogon', 'lastlogontimestamp', 'badpasswordtime')
            foreach ($timestampProperty in $timestampProperties) {
                if ($properties.ContainsKey($timestampProperty)) {
                    $properties[$timestampProperty] = Convert-LdapTimestamp -timestamp $properties[$timestampProperty]
                }
            }
        }
		
		$properties['domain'] = $Domain
        $records.Add([PSCustomObject]$properties)
    }

    # Convert the records to Dictionary<string, object> for the C# code
    [System.Collections.Generic.List[System.Collections.Generic.Dictionary[string, object]]]$recordsArray = New-Object 'System.Collections.Generic.List[System.Collections.Generic.Dictionary[string, object]]'
    foreach ($record in $records) {
        $dict = New-Object 'System.Collections.Generic.Dictionary[String, Object]'
        foreach ($prop in $record.PSObject.Properties) {
            $dict.Add($prop.Name, $prop.Value)
        }
        $recordsArray.Add($dict)
    }

    $CollectedResults = [DataCollector.ProcessorClass]::ProcessRecords($recordsArray, $numOfThreads)
    
    return $CollectedResults
}

# Load the necessary assemblies
Add-Type -AssemblyName System.DirectoryServices.AccountManagement
Add-Type -AssemblyName System.DirectoryServices

# Define the C# code for multithreaded processing
Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.Threading;
using System.Management.Automation;

namespace DataCollector
{
    public static class ProcessorClass
    {
        public static PSObject[] ProcessRecords(Dictionary<string, object>[] records, int numOfThreads)
        {
            Object[] results = ExecuteProcessing(records, numOfThreads);
            return Array.ConvertAll(results, item => (PSObject)item);
        }

        private static Object[] ExecuteProcessing(Dictionary<string, object>[] records, int numOfThreads)
        {
            int totalRecords = records.Length;
            IRecordHandler recordProcessor = new ActiveDirectoryRecordHandler();
            IResultsProcessor resultsHandler = new BasicResultsProcessor();
            int numberOfRecordsPerThread = totalRecords / numOfThreads;
            int remainders = totalRecords % numOfThreads;

            Thread[] threads = new Thread[numOfThreads];
            for (int i = 0; i < numOfThreads; i++)
            {
                int numberOfRecordsToProcess = numberOfRecordsPerThread;
                if (i == (numOfThreads - 1))
                {
                    numberOfRecordsToProcess += remainders;
                }

                Dictionary<string, object>[] sliceToProcess = new Dictionary<string, object>[numberOfRecordsToProcess];
                Array.Copy(records, i * numberOfRecordsPerThread, sliceToProcess, 0, numberOfRecordsToProcess);
                ProcessingThread processorThread = new ProcessingThread(i, recordProcessor, resultsHandler, sliceToProcess);
                threads[i] = new Thread(processorThread.ProcessThreadRecords);
                threads[i].Start();
            }
            foreach (Thread t in threads)
            {
                t.Join();
            }

            return resultsHandler.Complete();
        }

        class ProcessingThread
        {
            readonly int id;
            readonly IRecordHandler recordProcessor;
            readonly IResultsProcessor resultsHandler;
            readonly Dictionary<string, object>[] objectsToBeProcessed;

            public ProcessingThread(int id, IRecordHandler recordProcessor, IResultsProcessor resultsHandler, Dictionary<string, object>[] objectsToBeProcessed)
            {
                this.id = id;
                this.recordProcessor = recordProcessor;
                this.resultsHandler = resultsHandler;
                this.objectsToBeProcessed = objectsToBeProcessed;
            }

            public void ProcessThreadRecords()
            {
                for (int i = 0; i < objectsToBeProcessed.Length; i++)
                {
                    Object[] result = recordProcessor.ProcessRecord(objectsToBeProcessed[i]);
                    resultsHandler.ProcessResults(result);
                }
            }
        }

        interface IRecordHandler
        {
            PSObject[] ProcessRecord(Dictionary<string, object> record);
        }

        class ActiveDirectoryRecordHandler : IRecordHandler
        {
            public PSObject[] ProcessRecord(Dictionary<string, object> record)
            {
                try
                {
                    PSObject adObj = new PSObject();
                    foreach (var prop in record)
                    {
                        adObj.Members.Add(new PSNoteProperty(prop.Key, prop.Value));
                    }
                    return new PSObject[] { adObj };
                }
                catch (Exception e)
                {
                    Console.WriteLine("{0} Exception caught.", e);
                    return new PSObject[] { };
                }
            }
        }

        interface IResultsProcessor
        {
            void ProcessResults(Object[] t);
            Object[] Complete();
        }

        class BasicResultsProcessor : IResultsProcessor
        {
            private readonly Object lockObj = new Object();
            private readonly List<Object> processed = new List<Object>();

            public void ProcessResults(Object[] results)
            {
                lock (lockObj)
                {
                    if (results.Length != 0)
                    {
                        for (var i = 0; i < results.Length; i++)
                        {
                            processed.Add(results[i]);
                        }
                    }
                }
            }

            public Object[] Complete()
            {
                return processed.ToArray();
            }
        }
    }
}
"@

function Convert-LdapTimestamp {
    param([string]$timestamp)
    if ($timestamp -eq "0" -OR $timestamp -eq "9223372036854775807") {
        return "NEVER"
    }
    else {
        [datetime]$epoch = "1/1/1601"
        $date = $epoch.AddTicks($timestamp)
        return $date
    }
}

function GetSID-FromBytes {
	param (
        [byte[]]$sidBytes
    )
	
	$sid = New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)
	$stringSid = $sid.Value
	return $stringSid
}
