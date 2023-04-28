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

type hashStats struct {
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

	if secretsFile == "" {
		log.Fatal("No Secrets file passed")
	}

	secrets, err := loadDump(secretsFile)
	if err != nil {
		log.Fatalf("Error loading secrets: %s", err)
	}

	admins, err := loadAdmins(adminsFile)
	if err != nil {
		log.Fatalf("Error loading admins: %s", err)
	}

	parsedSecrets, err := parseSecrets(secrets, all, admins)
	if err != nil {
		log.Fatalf("Error parsing secrets %s", err)
	}

	if err := writeToCsv(parsedSecrets.ntlmCsvRecords, "duplicate_hashes.csv"); err != nil {
		log.Fatal(err)
	}

	if err := writeToCsv(parsedSecrets.lmHashes, "lm_hashes.csv"); err != nil {
		log.Fatal(err)
	}

	if err := writeLatex(parsedSecrets.latexLines); err != nil {
		log.Fatal(err)
	}

	printData(parsedSecrets.hashStats, all)
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

type parsedSecrets struct {
	mergedHashes   []mergedHash
	admins         map[string]string
	ntlmCsvRecords [][]string
	latexLines     string
	hashStats      hashStats
	lmHashes       [][]string
}

func parseSecrets(secrets []string, all bool, admins map[string]string) (parsedSecrets, error) {
	indexedHashes := make(map[string][]string)
	totalHashes := 0
	enabledAccounts := 0
	disabledAccounts := 0
	computerAccounts := 0
	blankPasswords := 0
	domains := make([]string, 0)
	lmHashes := make([][]string, 0)
	mergedHashes := make([]mergedHash, 0)
	duplicatedHashes := make(map[string]mergedHash)
	duplicatedAdmins := make([]string, 0)
	ntlmCsvRecords := [][]string{{"Count", "Hash", "Users"}}

	for _, secret := range secrets {
		h, err := parseLine(secret)
		if err != nil {
			// Is it worth trying to skip to the next iteration with 'continue'?
			// problem is that these files can contain thousands of lines. I don't want an error for each line.
			// then my only proposal is an errLineCount or something. if errLineCount >= 3 log.fatal...
			// log.Fatal(err)
			return parsedSecrets{}, fmt.Errorf("error reading file: %s", secrets)
		}

		totalHashes++

		if h.Enabled {
			enabledAccounts++
		} else {
			disabledAccounts++
		}

		if strings.Contains(h.User, "$") {
			computerAccounts++
		}

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

		// In go we can combine variable declarations into our if statement and they’ll be within the scope of that if statement. Like this:
		// In this example imagine everything before the ; is just on the previous line of code. But what it means is that the ok variable will get cleaned up at the end of the if block and
		// won’t exist outside of the scope of the if block. Otherwise most of it looks pretty standard, maybe if I get home and understand what you’re doing a bit more I’ll have more
		if _, ok := admins[h.User]; ok {
			admins[h.User] = h.NTLM
		}

		// The above instead of this.
		// _, ok := admins[h.User]
		// if ok {
		// 	admins[h.User] = h.NTLM
		// }

		// check if lm hash is blank value
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

	var latexLines []string

	for _, element := range mergedHashes {
		if element.Count > 1 {
			duplicatedHashes[element.Hash] = element
			ntlmCsvRecords = append(ntlmCsvRecords, []string{strconv.Itoa(element.Count), element.Hash, strings.Join(element.Users, " - ")})
			// validate hash length
			maskedHash := element.Hash[:5] + strings.Repeat("*", 12) + element.Hash[27:]
			latexLines = append(latexLines, fmt.Sprintf("\t\t%s & %d \\\\\n", maskedHash, element.Count))

		}
	}

	for admin, hash := range admins {
		if _, ok := duplicatedHashes[hash]; ok {
			duplicatedAdmins = append(duplicatedAdmins, admin)
		}
	}

	return parsedSecrets{
		hashStats: hashStats{
			hashes:           totalHashes,
			disabledAccounts: disabledAccounts,
			enabledAccounts:  enabledAccounts,
			domains:          domains,
			blankPasswords:   blankPasswords,
			duplicatedHashes: len(duplicatedHashes),
			computerAccounts: computerAccounts,
			duplicatedAdmins: duplicatedAdmins,
			lmHashes:         len(lmHashes),
		},
		mergedHashes:   mergedHashes,
		admins:         admins,
		lmHashes:       lmHashes,
		ntlmCsvRecords: ntlmCsvRecords,
		latexLines:     strings.TrimSpace(strings.Join(latexLines, "")),
	}, nil
}

func loadDump(secretsFile string) ([]string, error) {
	secrets := make([]string, 0)

	if secretsFile != "" {
		file, err := os.Open(secretsFile)
		if err != nil {
			return secrets, fmt.Errorf("error reading file: %s", secrets)
		}

		defer file.Close()

		sc := bufio.NewScanner(file)

		for sc.Scan() {
			secrets = append(secrets, sc.Text())
		}
	}

	return secrets, nil
}

func loadAdmins(adminsFile string) (map[string]string, error) {
	admins := make(map[string]string)

	if adminsFile != "" {
		file, err := os.Open(adminsFile)
		if err != nil {
			return admins, fmt.Errorf("error reading file: %s", adminsFile)
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
	return admins, nil
}

func writeToCsv(records [][]string, filename string) error {
	csvFile, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("error creating file: %s", filename)
	}

	csvWriter := csv.NewWriter(csvFile)

	csvWriter.WriteAll(records)

	return nil
}

func writeLatex(lines string) error {
	filename := "latex_table.txt"
	latexFile, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("error creating file: %s", filename)
	}

	latexString := strings.Replace(HASHES_LATEX, "%REPLACE_ME%", lines, 1)

	latexFile.WriteString(latexString)

	return nil
}

func parseLine(line string) (hash, error) {
	if line == "" || !strings.Contains(line, ":") {
		return hash{}, fmt.Errorf("line blank or incorrect format: %s", line)
	}

	s := strings.Split(line, ":")

	if len(s) < 7 || len(s[3]) != 32 {
		return hash{}, fmt.Errorf("error reading line: %s", line)
	}

	upn := strings.Split(s[0], "\\")

	h := hash{
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

	return h, nil
}

func printData(v hashStats, all bool) {
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
// Only output 'included admins' if admins file passed
