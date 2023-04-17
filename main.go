package main

import (
	"bufio"
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/fatih/color"
)

type hash struct {
	Domain  string
	User    string
	LM      string
	NTLM    string
	Enabled bool
}

type mergedHash struct {
	Users []string
	Count int
	Hash  string
}

type values struct {
	hashes           int
	enabledAccounts  int
	disabledAccounts int
	computerAccounts int
	duplicatedHashes int
	lmHashes         int
	blankPasswords   int
	domains          []string
	duplicatedAdmins []string
}

func main() {
	var all bool
	flag.BoolVar(&all, "all", false, "include disabled accounts in results")
	flag.Parse()

	secretsFile := flag.Arg(0)
	adminsFile := flag.Arg(1)

	indexedHashes := make(map[string][]string)
	mergedHashes := make([]mergedHash, 0)

	hashes := make([]string, 0)
	enabledAccounts := 0
	disabledAccounts := 0
	computerAccounts := 0
	blankPasswords := 0
	duplicatedHashes := make(map[string]mergedHash)
	lmHashes := make([][]string, 0)
	domains := make([]string, 0)
	duplicatedAdmins := make([]string, 0)
	csvRecords := [][]string{{"Count", "Hash", "Users"}}

	admins := make(map[string]string)

	if adminsFile != "" {
		file, err := os.Open(adminsFile)

		if err != nil {
			log.Fatalf("Error reading file: %s", err)
		}

		defer file.Close()

		sc := bufio.NewScanner(file)

		for sc.Scan() {
			admin := sc.Text()
			if admin != "" {
				admins[admin] = ""
			}
		}
		file.Close()
	}

	if secretsFile != "" {
		file, err := os.Open(secretsFile)

		if err != nil {
			log.Fatalf("Error reading file: %s", err)
		}

		defer file.Close()

		sc := bufio.NewScanner(file)

		for sc.Scan() {
			h := parseLine(sc.Text())

			if h.Enabled {
				enabledAccounts++
			} else {
				disabledAccounts++
			}

			if strings.Contains(h.User, "$") {
				computerAccounts++
			}

			// not sure i actually need a slice with all hashes in, started out this way, kept it just in case
			hashes = append(hashes, h.NTLM)

			if !all && !h.Enabled {
				continue
			}

			if strings.Contains(h.NTLM, "31d6cfe0d16ae931b73c59d7e0c089c0") {
				blankPasswords++
			}

			if h.Domain != "" && !contains(domains, strings.ToLower(h.Domain)) {
				domains = append(domains, strings.ToLower(h.Domain))
			}

			indexedHashes[h.NTLM] = append(indexedHashes[h.NTLM], h.User)

			_, ok := admins[h.User]
			if ok {
				admins[h.User] = h.NTLM
			}

			if !strings.Contains(h.LM, "aad3b435b51404eeaad3b435b51404ee") {
				lmHashes = append(lmHashes, []string{h.User, h.LM})
			}

		}

		for key, element := range indexedHashes {
			mergedHashes = append(mergedHashes, mergedHash{Count: len(element), Hash: key, Users: element})

		}

		sort.Slice(mergedHashes, func(i, j int) bool {
			return mergedHashes[i].Count > mergedHashes[j].Count
		})

		// Should i initalise this here?
		// Could also be an array and then.Join() at the end?
		lines := ``

		for _, element := range mergedHashes {
			if element.Count > 1 {
				duplicatedHashes[element.Hash] = element
				csvRecords = append(csvRecords, []string{strconv.Itoa(element.Count), element.Hash, strings.Join(element.Users, " - ")})
				maskedHash := element.Hash[:5] + strings.Repeat("*", 12) + element.Hash[27:]
				// Anyway to avoid the TrimSpace() needed below?
				lines += fmt.Sprintf("\t\t%s & %d \\\\\n", maskedHash, element.Count)

			}
		}

		for admin, hash := range admins {
			_, ok := duplicatedHashes[hash]
			if ok {
				duplicatedAdmins = append(duplicatedAdmins, admin)
			}
		}

		// remove the extra line at the end
		lines = strings.TrimSpace(lines)

		valuesToPrint := values{
			disabledAccounts: disabledAccounts,
			hashes:           len(hashes),
			domains:          domains,
			blankPasswords:   blankPasswords,
			duplicatedHashes: len(duplicatedHashes),
			enabledAccounts:  enabledAccounts,
			computerAccounts: computerAccounts,
			lmHashes:         len(lmHashes),
			duplicatedAdmins: duplicatedAdmins,
		}

		writeToCsv(csvRecords, "duplicate_hashes.csv")
		writeToCsv(lmHashes, "lm_hashes.csv")

		writeLatex(lines)

		printData(valuesToPrint, all)

	}

}

// Could of course just import the slices pkg, but this was a simple stack overflow solution
func contains(elems []string, v string) bool {
	for _, s := range elems {
		if v == s {
			return true
		}
	}
	return false
}

func writeToCsv(records [][]string, filename string) {
	csvFile, err := os.Create(filename)

	if err != nil {
		log.Fatalf("error creating file: %s", err)
	}

	csvWriter := csv.NewWriter(csvFile)

	csvWriter.WriteAll(records)
}

func writeLatex(lines string) {
	latexFile, err := os.Create("latex_table.txt")

	if err != nil {
		log.Fatalf("error creating file: %s", err)
	}

	latexString := strings.Replace(HASHES_LATEX, "%REPLACE_ME%", lines, 1)

	latexFile.WriteString(latexString)

}

func parseLine(line string) hash {
	if line == "" || !strings.Contains(line, ":") {
		log.Fatal("string empty or incorrect format")
	}

	s := strings.Split(line, ":")

	if len(s) < 7 {
		log.Fatal("Incorrect hash format")
	}

	upn := strings.Split(s[0], "\\")

	h := hash{
		//User:    s[0], // + s[6] - to add enabled to name
		LM:      s[2],
		NTLM:    s[3],
		Enabled: strings.Contains(s[6], "Enabled"),
	}

	if len(upn) > 1 {
		h.Domain = upn[0]
		h.User = upn[1]
	} else {
		h.User = upn[0]
	}

	return h

}

func printData(v values, all bool) {
	printRed := color.New(color.Bold, color.FgRed).PrintlnFunc()
	printGreen := color.New(color.Bold, color.FgGreen).PrintlnFunc()
	printYellow := color.New(color.Bold, color.FgYellow).PrintlnFunc()

	fmt.Println("\nTotal hashes:\t\t", v.hashes)
	fmt.Println("Enabled Accounts:\t", v.enabledAccounts)
	fmt.Println("Disabled Accounts:\t", v.disabledAccounts)
	fmt.Println("Computer Accounts:\t", v.computerAccounts)

	if all {
		fmt.Println("\nDisabled Accounts INCLUDED")
	} else {
		fmt.Println("\nDisabled Accounts NOT included")
	}

	if v.lmHashes > 0 {
		printRed("LM Hashes:\t\t", v.lmHashes)
	} else {
		printGreen("LM Hashes:\t\t", v.lmHashes)
	}

	if v.blankPasswords > 0 {
		printRed("Blank Passwords:\t", v.blankPasswords)
	} else {
		printGreen("Blank Passwords:\t", v.blankPasswords)
	}

	if v.duplicatedHashes > 0 {
		printRed("Duplicated Hashes:\t", v.duplicatedHashes)
	} else {
		printGreen("Duplicated Hashes:\t", v.duplicatedHashes)
	}

	fmt.Println("Domains:\t\t", v.domains)
	if len(v.duplicatedAdmins) > 0 {
		printRed("Included Admins:\t", v.duplicatedAdmins)
	} else {
		printGreen("Included Admins:\t", v.duplicatedAdmins)

	}

	printYellow("\nLatex Table output to latex_table.txt")
	printYellow("CSV output to duplicated_hashes.txt")

}

// TODO:
// -threshhold for duplicates count 2,3,4 / exclude default to more than 1
// stop when line blank
