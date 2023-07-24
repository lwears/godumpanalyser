package main

const HASHES_LATEX = `\begin{table}[H]
    \centering
    \begin{tabular}{l | l}
        \textbf{Hash value} & \textbf{Count} \\
        \hline
        %REPLACE_ME%
        \hline
    \end{tabular}
    \caption{Passwords most shared between AD accounts}
\end{table}
`

const SHARED_HASHES = `
\begin{table}[H]
    \centering
    \begin{tabular}{ l | l }
        \textbf{Hash value} & \textbf{Accounts} \\
        \hline  
        %REPLACE_ME%
        \hline
    \end{tabular}
    \caption{Domain Admins sharing passwords}
\end{table}
`
