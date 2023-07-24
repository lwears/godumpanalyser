package main

import (
	"bufio"
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/fatih/color"
	"github.com/pkg/errors"
	"github.com/thoas/go-funk"
)

const BLANK_NTLM = "31d6cfe0d16ae931b73c59d7e0c089c0"

const BLANK_LM = "aad3b435b51404eeaad3b435b51404ee"

type Options struct {
	SecretsFile     string
	AdminsFile      string
	IncludeDisabled bool
}

type HashStat struct {
	users []string
	count int
	hash  string
}

type IndexedHashes = map[string][]string

type Stats struct {
	hashes           int
	enabledAccounts  int
	disabledAccounts int
	computerAccounts int
	blankPasswords   int
	domains          []string
	lmHashes         [][]string
	admins           map[string]string
}

type Hash struct {
	Domain     string
	User       string
	LM         string
	NTLM       string
	Enabled    bool
	isComputer bool
	isAdmin    bool
}

type DuplicatedHashes = map[string]HashStat

type BuiltStats struct {
	latexLines       []string
	ntlmCsvRecords   [][]string
	duplicatedHashes DuplicatedHashes
}

func main() {

	var stats = Stats{
		admins: make(map[string]string),
	}

	indexedHashes := make(map[string][]string)

	opts, err := ReadOptions()
	if err != nil {
		log.Fatal()
	}

	err = LoadAdmins(opts.AdminsFile, &stats)
	if err != nil {
		log.Fatalf("Error loading admins: %s", err)
	}

	err = LoadFileAndProcess(opts.SecretsFile, opts.IncludeDisabled, &stats, indexedHashes)
	if err != nil {
		log.Fatalf("Error loading secrets: %s", err)
	}

	builtStats := BuildMoreStats(indexedHashes)

	duplicatedAdmins := FindDuplicateAdmins(builtStats.duplicatedHashes, stats.admins)

	stats.PrintSummary(len(builtStats.duplicatedHashes), duplicatedAdmins, opts.IncludeDisabled)

	if err := WriteToCSV(builtStats.ntlmCsvRecords, "duplicate_hashes.csv"); err != nil {
		log.Fatal(err)
	}

	if err := WriteToCSV(stats.lmHashes, "lm_hashes.csv"); err != nil {
		log.Fatal(err)
	}

	if err := WriteLaTeX(builtStats.latexLines); err != nil {
		log.Fatal(err)
	}

}

func ReadOptions() (*Options, error) {
	cfg := &Options{}
	flag.BoolVar(&cfg.IncludeDisabled, "all", false, "include disabled accounts in results")
	flag.Parse()

	cfg.SecretsFile = flag.Arg(0)
	cfg.AdminsFile = flag.Arg(1)

	if cfg.SecretsFile == "" {
		log.Fatal("No Secrets file passed")
	}

	return cfg, nil
}

func LoadAdmins(adminsFile string, stats *Stats) error {
	if adminsFile == "" {
		return errors.New("Empty admins argument")
	}

	file, err := os.Open(adminsFile)
	if err != nil {
		return fmt.Errorf("error reading file: %s", adminsFile)
	}

	defer file.Close()

	sc := bufio.NewScanner(file)

	for sc.Scan() {
		admin := strings.TrimSpace(strings.ToLower(sc.Text()))
		if admin != "" {
			stats.admins[admin] = ""
		}
	}
	file.Close()
	return nil
}

func LoadFileAndProcess(secretsFile string, includeDisabled bool, stats *Stats, idxHashes IndexedHashes) error {
	file, err := os.Open(secretsFile)
	if err != nil {
		return fmt.Errorf("error reading file: %s", secretsFile)
	}

	defer file.Close()

	sc := bufio.NewScanner(file)

	for sc.Scan() {
		ph, err := ParseHash(sc.Text(), stats.admins)
		if err != nil {
			// Is it worth trying to skip to the next iteration with 'continue'?
			// problem is that these files can contain thousands of lines. I don't want an error for each line.
			// then my only proposal is an errLineCount or something. if errLineCount >= 3 log.fatal...
			// log.Fatal(err)
			return fmt.Errorf("error reading hash line: %s", sc.Text())
		}
		AddToStats(ph, stats, includeDisabled)
		idxHashes[ph.NTLM] = append(idxHashes[ph.NTLM], ph.User)
	}
	return nil
}

func AddToStats(h Hash, stats *Stats, all bool) {
	stats.hashes++
	if h.Enabled {
		stats.enabledAccounts++
	} else {
		stats.disabledAccounts++
	}

	if h.isComputer {
		stats.computerAccounts++
	}

	if !all && !h.Enabled {
		return
	}

	if strings.Contains(h.NTLM, BLANK_NTLM) {
		stats.blankPasswords++
	}

	if h.Domain != "" && !contains(stats.domains, strings.ToLower(h.Domain)) {
		stats.domains = append(stats.domains, strings.ToLower(h.Domain))
	}

	if !strings.Contains(h.LM, BLANK_LM) {
		stats.lmHashes = append(stats.lmHashes, []string{h.User, h.LM})
	}

	if h.isAdmin {
		stats.admins[h.User] = h.NTLM
	}
}

func BuildMoreStats(idxHashes IndexedHashes) BuiltStats {

	keys := funk.Keys(idxHashes)

	initialValue := BuiltStats{duplicatedHashes: make(map[string]HashStat), latexLines: make([]string, 0), ntlmCsvRecords: make([][]string, 0)}

	r := funk.Reduce(keys, func(acc BuiltStats, key string) BuiltStats {
		value := idxHashes[key]
		if len(value) > 1 {
			acc.duplicatedHashes[key] = HashStat{count: len(value), hash: key, users: value}
			acc.ntlmCsvRecords = append(acc.ntlmCsvRecords, []string{strconv.Itoa(len(value)), key, strings.Join(value, " - ")})
			maskedHash := key[:4] + strings.Repeat("*", 14) + key[28:]
			acc.latexLines = append(acc.latexLines, fmt.Sprintf("\t\t%s & %d \\\\\n", maskedHash, len(value)))
		}
		return acc
	}, initialValue)

	result := r.(BuiltStats)

	return result
}

func FindDuplicateAdmins(dupHashes DuplicatedHashes, admins map[string]string) []string {

	duplicatedAdmins := make([]string, 0)
	for admin, hash := range admins {
		if _, ok := dupHashes[hash]; ok {
			duplicatedAdmins = append(duplicatedAdmins, strings.ToLower(admin))
		}
	}
	return duplicatedAdmins
}

func WriteToCSV(records [][]string, filename string) error {
	csvFile, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("error creating file: %s", filename)
	}

	csvWriter := csv.NewWriter(csvFile)

	csvWriter.WriteAll(records)

	color.New(color.Bold, color.FgYellow).Printf("\nCSV File: %q saved", filename)

	return nil
}

func WriteLaTeX(lines []string) error {
	builder := strings.Builder{}
	filename := "latex_table.txt"
	latexFile, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("error creating file: %s", filename)
	}

	for _, line := range lines {
		builder.WriteString(line)
	}

	latexString := strings.Replace(HASHES_LATEX, "%REPLACE_ME%", strings.TrimSpace(builder.String()), 1)

	latexFile.WriteString(latexString)

	color.New(color.Bold, color.FgYellow).Printf("\nLatex Table output to %q\n", filename)

	return nil
}

func ParseHash(line string, admins map[string]string) (Hash, error) {
	if line == "" || !strings.Contains(line, ":") {
		return Hash{}, fmt.Errorf("line blank or incorrect format: %s", line)
	}

	s := strings.Split(line, ":")

	if len(s) < 7 || len(s[3]) != 32 {
		return Hash{}, fmt.Errorf("error reading line: %s", line)
	}

	upn := strings.Split(strings.ToLower(s[0]), "\\")

	h := Hash{
		LM:         s[2],
		NTLM:       s[3],
		Enabled:    strings.Contains(s[6], "Enabled"),
		isComputer: strings.Contains(s[0], "$"),
	}

	if len(upn) > 1 {
		h.Domain = upn[0]
		h.User = upn[1]
	} else {
		h.User = upn[0]
	}

	if _, ok := admins[h.User]; ok {
		h.isAdmin = true
	}

	return h, nil
}

func (s *Stats) PrintSummary(dupHashes int, duplicatedAdmins []string, all bool) {
	red := color.New(color.Bold, color.FgRed)
	green := color.New(color.Bold, color.FgGreen)

	printRedGreen := func(p bool, args ...any) {
		if p {
			red.Println(args...)
		} else {
			green.Println(args...)
		}
	}

	fmt.Println("\nTotal hashes:\t\t", s.hashes)
	fmt.Println("Enabled Accounts:\t", s.enabledAccounts)
	fmt.Println("Disabled Accounts:\t", s.disabledAccounts)
	fmt.Println("Computer Accounts:\t", s.computerAccounts)

	if all {
		fmt.Println("\nDisabled Accounts INCLUDED")
	} else {
		fmt.Println("\nDisabled Accounts NOT included")
	}

	printRedGreen(len(s.lmHashes) > 0, "LM Hashes:\t\t", len(s.lmHashes))
	printRedGreen(s.blankPasswords > 0, "Blank Passwords:\t", s.blankPasswords)
	printRedGreen(dupHashes > 0, "Duplicated Hashes:\t", dupHashes)

	fmt.Println("Domains:\t\t", s.domains)

	printRedGreen(len(duplicatedAdmins) > 0, "Included Admins:\t", duplicatedAdmins)

}

// Could of course just import the slices pkg, but this was a simple stack overflow solution
func contains(elems []string, stats string) bool {
	for _, s := range elems {
		if stats == s {
			return true
		}
	}
	return false
}

// TODO:
// -threshhold for duplicates count 2,3,4 / exclude default to more than 1
// Only output 'included admins' if admins file passed
