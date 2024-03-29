package main

import (
	"bufio"
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/fatih/color"
)

const BLANK_NTLM = "31d6cfe0d16ae931b73c59d7e0c089c0"

const BLANK_LM = "aad3b435b51404eeaad3b435b51404ee"

const LATEX_FILENMAE = "latex_table.txt"

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
	stats := Stats{
		admins: make(map[string]string),
	}

	indexedHashes := make(IndexedHashes)

	opts, err := ReadOptions()
	if err != nil {
		log.Fatal()
	}

	if err := LoadAdmins(opts.AdminsFile, &stats); err != nil {
		log.Fatalf("Error loading admins: %s", err)
	}

	if err := LoadFileAndProcess(opts.SecretsFile, opts.IncludeDisabled, &stats, indexedHashes); err != nil {
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

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(),
			"godumpanalyser\nDeveloped for analysing secretsdump output\n")
		fmt.Fprintf(flag.CommandLine.Output(), "Copyright 2023\n")
		fmt.Fprintln(flag.CommandLine.Output(), "Usage information:")
		flag.PrintDefaults()
	}

	flag.BoolVar(&cfg.IncludeDisabled, "all", false, "include disabled accounts in results")
	flag.Parse()

	cfg.SecretsFile = flag.Arg(0)
	cfg.AdminsFile = flag.Arg(1)

	if cfg.SecretsFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	return cfg, nil
}

func LoadAdmins(adminsFile string, stats *Stats) error {
	if adminsFile == "" {
		return nil
	}

	file, err := os.Open(adminsFile)
	if err != nil {
		return fmt.Errorf("error reading file: %s", err)
	}

	defer file.Close()

	sc := bufio.NewScanner(file)

	for sc.Scan() {
		admin := strings.TrimSpace(strings.ToLower(sc.Text()))
		if admin != "" {
			stats.admins[admin] = ""
		}
	}
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
			// then my only idea is an errLineCount or something. if errLineCount >= 3 log.fatal...
			// log.Fatal(err)
			return fmt.Errorf("error reading hash line: %s", sc.Text())
		}
		stats.AddToStats(ph, includeDisabled)

		idxHashes[ph.NTLM] = append(idxHashes[ph.NTLM], ph.User)
	}

	sort.Slice(stats.lmHashes, func(i, j int) bool {
		return len(stats.lmHashes[i]) < len(stats.lmHashes[j])
	})

	return nil
}

func (s *Stats) AddToStats(h Hash, all bool) {
	s.hashes++
	if h.Enabled {
		s.enabledAccounts++
	} else {
		s.disabledAccounts++
	}

	if h.isComputer {
		s.computerAccounts++
	}

	if !all && !h.Enabled {
		return
	}

	if strings.Contains(h.NTLM, BLANK_NTLM) {
		s.blankPasswords++
	}

	if h.Domain != "" && !slices.Contains(s.domains, strings.ToLower(h.Domain)) {
		s.domains = append(s.domains, strings.ToLower(h.Domain))
	}

	if !strings.Contains(h.LM, BLANK_LM) {
		s.lmHashes = append(s.lmHashes, []string{h.User, h.LM})
	}

	if h.isAdmin {
		s.admins[h.User] = h.NTLM
	}
}

// rename
func BuildMoreStats(idxHashes IndexedHashes) BuiltStats {
	builtStats := BuiltStats{duplicatedHashes: make(map[string]HashStat), latexLines: make([]string, 0), ntlmCsvRecords: make([][]string, 0)}

	pairs := ToPairs[string, []string](idxHashes)

	sort.Slice(pairs, func(i, j int) bool {
		return len(pairs[i].Value) > len(pairs[j].Value)
	})

	for _, pair := range pairs {
		if len(pair.Value) > 1 {
			hashStat := HashStat{count: len(pair.Value), hash: pair.Key, users: pair.Value}
			builtStats.duplicatedHashes[pair.Key] = hashStat
			builtStats.ntlmCsvRecords = append(builtStats.ntlmCsvRecords, []string{strconv.Itoa(len(pair.Value)), pair.Key, strings.Join(pair.Value, " - ")})
			maskedHash := pair.Key[:4] + strings.Repeat("*", 14) + pair.Key[28:]
			builtStats.latexLines = append(builtStats.latexLines, fmt.Sprintf("\t\t%s & %d \\\\\n", maskedHash, len(pair.Value)))
		}
	}

	return builtStats
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
	latexFile, err := os.Create(LATEX_FILENMAE)
	if err != nil {
		return fmt.Errorf("error creating file: %s", err)
	}

	for _, line := range lines {
		builder.WriteString(line)
	}

	latexString := strings.Replace(HASHES_LATEX, "%REPLACE_ME%", strings.TrimSpace(builder.String()), 1)

	latexFile.WriteString(latexString)

	color.New(color.Bold, color.FgYellow).Printf("\nLatex Table output to %q\n", LATEX_FILENMAE)

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
		Enabled:    !strings.Contains(strings.ToLower(s[6]), "disabled"),
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

	if len(s.admins) > 0 {
		printRedGreen(len(duplicatedAdmins) > 0, "Included Admins:\t", duplicatedAdmins)
	}
}

type KeyValue[K comparable, V any] struct {
	Key   K
	Value V
}

func ToPairs[K string, V any](slice map[K]V) []KeyValue[K, V] {
	pairs := make([]KeyValue[K, V], len(slice))

	for key, value := range slice {
		pairs = append(pairs, KeyValue[K, V]{Key: key, Value: value})
	}
	return pairs
}

// TODO:
// -threshhold for duplicates count 2,3,4 / exclude default to more than 1
