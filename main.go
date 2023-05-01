package main

import (
	"bufio"
	"bytes"
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

type Options struct {
	SecretsFile     string
	AdminsFile      string
	IncludeDisabled bool
}

func main() {
	opts, err := ReadOptions()
	if err != nil {
		log.Fatal(err)
	}

	dump, err := LoadDump(opts.SecretsFile, opts.AdminsFile)
	if err != nil {
		log.Fatal(err)
	}

	report := dump.GenerateReport(opts.IncludeDisabled)

	report.PrintSummary()

	if err := report.SaveDuplicates("duplicate_hashes.csv"); err != nil {
		log.Fatal(err)
	}
	if err := report.SaveLMHashes("lm_hashes.csv"); err != nil {
		log.Fatal(err)
	}
	if err := report.SaveLaTeX("latex_table.txt"); err != nil {
		log.Fatal(err)
	}
}

func ReadOptions() (*Options, error) {
	cfg := &Options{}
	flag.BoolVar(&cfg.IncludeDisabled, "all", false, "include disabled accounts in results")
	flag.Parse()

	cfg.SecretsFile = flag.Arg(0)
	if cfg.SecretsFile == "" {
		return nil, fmt.Errorf("no secrets file passed")
	}

	cfg.AdminsFile = flag.Arg(1)
	if cfg.AdminsFile == "" {
		return nil, fmt.Errorf("no admins file passed")
	}

	return cfg, nil
}

type Dump struct {
	AdminUsers []string
	Hashes     []*Hash
}

func LoadDump(secretsFile, adminsFile string) (*Dump, error) {
	dump := &Dump{}

	adminUsers, err := readLines(adminsFile)
	if err != nil {
		return nil, ErrReadingFile
	}
	dump.AdminUsers = adminUsers

	secrets, err := readLines(secretsFile)
	if err != nil {
		return nil, ErrReadingFile
	}
	for _, secret := range secrets {
		hash, err := parseHash(secret)
		if err != nil {
			return nil, err
		}
		dump.Hashes = append(dump.Hashes, hash)
	}

	return dump, nil
}

type Report struct {
	Hashes           int
	EnabledAccounts  int
	DisabledAccounts int
	ComputerAccounts int
	BlankPasswords   int
	DuplicateHashes  []DuplicateHash
	LMHashes         []*Hash
	Domains          []string
	DuplicateAdmins  []string

	DisabledUsersIncluded bool
}

type DuplicateHash struct {
	NTLM   string
	Hashes []*Hash
}

func (d *Dump) GenerateReport(includeDisabled bool) Report {
	var r Report

	r.Hashes = len(d.Hashes)
	r.EnabledAccounts = countIf(d.Hashes, func(h *Hash) bool { return h.Enabled })
	r.DisabledAccounts = r.Hashes - r.EnabledAccounts
	r.ComputerAccounts = countIf(d.Hashes, func(h *Hash) bool { return h.IsComputer() })
	r.BlankPasswords = countIf(d.Hashes, func(h *Hash) bool { return h.IsBlank() })
	r.DisabledUsersIncluded = includeDisabled
	r.Domains = collectDomains(d.Hashes, includeDisabled)
	r.LMHashes = selectIf(d.Hashes, func(h *Hash) bool { return h.IsLM() })

	idx := d.indexHashes()
	r.DuplicateHashes = collectDuplicates(idx, includeDisabled)
	r.DuplicateAdmins = collectDuplicateAdmins(idx, includeDisabled)

	return r
}

type HashIndex struct {
	byAdminUser map[string]*Hash
	byNTLM      map[string][]*Hash
}

func (d *Dump) indexHashes() *HashIndex {
	idx := &HashIndex{
		byAdminUser: make(map[string]*Hash),
		byNTLM:      make(map[string][]*Hash),
	}

	for _, name := range d.AdminUsers {
		idx.byAdminUser[name] = nil
	}

	for _, hash := range d.Hashes {
		idx.byNTLM[hash.NTLM] = append(idx.byNTLM[hash.NTLM], hash)
		if _, ok := idx.byAdminUser[hash.User]; ok {
			idx.byAdminUser[hash.User] = hash
		}
	}

	return idx
}

type Hash struct {
	Domain  string
	User    string
	LM      string
	NTLM    string
	Enabled bool
}

func parseHash(secret string) (*Hash, error) {
	if secret == "" || !strings.Contains(secret, ":") {
		return nil, fmt.Errorf("line blank or incorrect format: %s", secret)
	}

	s := strings.Split(secret, ":")

	if len(s) < 7 || len(s[3]) != 32 {
		return nil, fmt.Errorf("error reading line: %s", secret)
	}

	upn := strings.Split(s[0], "\\")

	h := &Hash{
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

func (h *Hash) IsComputer() bool {
	return strings.Contains(h.User, "$")
}

func (h *Hash) IsBlank() bool {
	return strings.Contains(h.NTLM, "31d6cfe0d16ae931b73c59d7e0c089c0")
}

func (h *Hash) IsLM() bool {
	return !strings.Contains(h.LM, "aad3b435b51404eeaad3b435b51404ee")
}

func (h *Hash) MaskedNTLM() string {
	if len(h.NTLM) < 32 {
		return ""
	}
	return h.NTLM[:5] + strings.Repeat("*", 12) + h.NTLM[27:]
}

func (r *Report) SaveDuplicates(fn string) error {
	f, err := os.Create(fn)
	if err != nil {
		return ErrCreatingFile
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()

	if err := w.Write([]string{"Count", "Hash", "Users"}); err != nil {
		return err
	}

	for _, dh := range r.DuplicateHashes {
		count := strconv.Itoa(len(dh.Hashes))
		hash := dh.Hashes[0].NTLM
		var users []string
		for _, h := range dh.Hashes {
			users = append(users, h.User)
		}
		if err := w.Write([]string{count, hash, strings.Join(users, " - ")}); err != nil {
			return err
		}
	}

	color.New(color.Bold, color.FgYellow).Printf("CSV duplicate hashes saved to %q", fn)
	fmt.Println()

	return nil
}

func (r *Report) SaveLMHashes(fn string) error {
	f, err := os.Create(fn)
	if err != nil {
		return ErrCreatingFile
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()

	for _, h := range r.LMHashes {
		if err := w.Write([]string{h.User, h.LM}); err != nil {
			return err
		}
	}

	color.New(color.Bold, color.FgYellow).Printf("CSV LM hashes saved to %q", fn)
	fmt.Println()

	return nil
}

func (r *Report) SaveLaTeX(fn string) error {
	f, err := os.Create(fn)
	if err != nil {
		return ErrCreatingFile
	}

	var buf bytes.Buffer
	const lineFormat = "\t\t%s & %d \\\\\n"
	for _, dup := range r.DuplicateHashes {
		buf.WriteString(fmt.Sprintf(lineFormat, dup.Hashes[0].MaskedNTLM(), len(dup.Hashes)))
	}

	table := bytes.TrimSpace(buf.Bytes())
	latex := strings.Replace(HASHES_LATEX, "%REPLACE_ME%", string(table), 1)
	if _, err := f.WriteString(latex); err != nil {
		return err
	}

	color.New(color.Bold, color.FgYellow).Printf("Latex Table saved to %q", fn)
	fmt.Println()

	return nil
}

func (r *Report) PrintSummary() {
	red := color.New(color.Bold, color.FgRed)
	green := color.New(color.Bold, color.FgGreen)
	printRedGreen := func(p bool, args ...any) {
		if p {
			red.Println(args...)
		} else {
			green.Println(args...)
		}
	}

	fmt.Println("Total hashes:\t\t", r.Hashes)
	fmt.Println("Enabled Accounts:\t", r.EnabledAccounts)
	fmt.Println("Disabled Accounts:\t", r.DisabledAccounts)
	fmt.Println("Computer Accounts:\t", r.ComputerAccounts)
	if r.DisabledUsersIncluded {
		fmt.Println("\nDisabled Accounts INCLUDED")
	} else {
		fmt.Println("\nDisabled Accounts NOT included")
	}
	printRedGreen(len(r.LMHashes) > 0, "LM Hashes:\t\t", len(r.LMHashes))
	printRedGreen(r.BlankPasswords > 0, "Blank Passwords:\t", r.BlankPasswords)
	printRedGreen(len(r.DuplicateHashes) > 0, "Duplicated Hashes:\t", len(r.DuplicateHashes))
	fmt.Println("Domains:\t\t", r.Domains)
	printRedGreen(len(r.DuplicateAdmins) > 0, "Included Admins:\t", r.DuplicateAdmins)
	fmt.Println()
}

func collectDomains(hs []*Hash, includeDisabled bool) []string {
	domains := map[string]struct{}{}
	for _, h := range hs {
		if h.Enabled || includeDisabled {
			domains[h.Domain] = struct{}{}
		}
	}
	list := make([]string, 0, len(domains))
	for d := range domains {
		list = append(list, d)
	}
	return list
}

func collectDuplicates(idx *HashIndex, includeDisabled bool) []DuplicateHash {
	var dups []DuplicateHash

	for ntlm, hashes := range idx.byNTLM {
		if len(hashes) > 1 {
			dup := DuplicateHash{NTLM: ntlm}
			for _, h := range hashes {
				if !(h.Enabled || includeDisabled) {
					continue
				}
				dup.Hashes = append(dup.Hashes, h)
			}
			if len(dup.Hashes) > 1 {
				dups = append(dups, dup)
			}
		}
	}

	sort.Slice(dups, func(i, j int) bool { return len(dups[i].Hashes) > len(dups[j].Hashes) })

	return dups
}

func collectDuplicateAdmins(idx *HashIndex, includeDisabled bool) []string {
	var admins []string
	for admin, hash := range idx.byAdminUser {
		if !(hash.Enabled || includeDisabled) {
			continue
		}
		if len(idx.byNTLM[hash.NTLM]) > 1 {
			admins = append(admins, admin)
		}
	}
	return admins
}

func countIf[T any](s []T, p func(T) bool) int {
	cnt := 0
	for _, v := range s {
		if p(v) {
			cnt++
		}
	}
	return cnt
}

func selectIf[T any](s []T, p func(T) bool) []T {
	var r []T
	for _, v := range s {
		if p(v) {
			r = append(r, v)
		}
	}
	return r
}

func readLines(fn string) ([]string, error) {
	f, err := os.Open(fn)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if err := sc.Err(); err != nil {
			return nil, err
		}
		lines = append(lines, sc.Text())
	}

	return lines, nil
}
