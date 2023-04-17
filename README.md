# Go-Pass-Parser
Golang Password Parser for output AFTER first parsing with impackets secretsdump

## AD Dump Analyser

This will parse the ADdump.ntds returned from impackets secretsdump and give some general statstics.
It will output a CSV file of duplicated passwords in the format Count,Hash,Users
It will also output a simple text file with the latex code to copy and paste the duplicated hashes directly into the report.

## Input Example

```
domain.local\User1:2202:aad3b435b51404eeaad3b435b51404e1:64F12CDDAA88057E06A81B54E73B949B::: (status=Enabled)
```

> **_NOTE:_** The inclusion of the account status at the end is not default when using secretsdump

## Useage example

You can pass 2 files as parameters


```shell
go run . addump.txt admins.txt
```

## Flags

`-all` This will force it to include all accounts

## Output 

```shell
Total hashes: ##
Enabled Accounts ##
Disabled Accounts: ##
Computer Accounts: ##

Disabled Accounts Included / Not Included
LM Hashes: ##
Blank Passwords: ##
Duplicated Hashes: ##
Domains: "[domain.local domain2.local]"
Admins: ["domainAdmin1"]

Latex Table output to latex_table.txt
CSV output to duplicated_hashes.txt
```

## Todo

Implement this library: https://github.com/C-Sto/gosecretsdump

duplicate threshold count flag `-threshold` 2/3/4/whatever

goroutines to concurrently read all lines from file and then process multiple at once