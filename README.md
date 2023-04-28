# Go-Pass-Parser
Golang Password Parser for output AFTER first parsing with impackets secretsdump

## AD Dump Analyser

This will parse the ADdump.ntds returned from impackets secretsdump (`-user-status`) and give some general statstics.
It will output a CSV file of duplicated passwords in the format `Count,Hash,Users`
It will also output a simple text file with the latex code to copy and paste the duplicated hashes directly into the report.

## Input Example

```
domain.local\User1:2202:aad3b435b51404eeaad3b435b51404e1:64F12CDDAA88057E06A81B54E73B949B::: (status=Enabled)
```

> **_NOTE:_** The inclusion of the account status at the end is not default when using secretsdump `-user-status`

## Useage example

You can pass 2 files as parameters


```shell
go run . examples.txt admins.txt
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

### LaTeX Output Example

```latex
\begin{table}[H]
    \centering
    \begin{tabular}{l | l}
        \textbf{Hash value} & \textbf{Count} \\
        \hline
        0e574************c1769 & 3 \\
		76C3C************80A15 & 3 \\
		58A47************FDB71 & 2 \\
		7B23F************BEB5B & 2 \\
		F7A80************E967C & 2 \\
        \hline
    \end{tabular}
    \caption{Passwords most shared between AD accounts}
\end{table}

```

## Todo

Implement this library: https://github.com/C-Sto/gosecretsdump

duplicate threshold count flag `-threshold` 2/3/4/whatever

goroutines to concurrently read all lines from file and then process multiple at once
