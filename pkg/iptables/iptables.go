package iptables

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var (
	ruleRegexp = regexp.MustCompile(`^\[(?P<cnt>\d+):(?P<byte>\d+)\] -A (?P<chain>[^ ]+) (.*?) ?-j (?P<target>.*)$`)
)

type IPTables struct {
	tables map[string]*Table
}

type Table struct {
	name   string
	chains map[string]*Chain
}

type Chain struct {
	name                  string
	isDefaultPolicyAccept bool
	rules                 []*Rule
}

type Rule struct {
	args       string
	target     string
	pktCount   int
	bytesCount int
}

func NewFromIPTablesSave(output string) (*IPTables, error) {
	ipt := &IPTables{
		tables: make(map[string]*Table),
	}

	lines := strings.Split(output, "\n")
	if err := ipt.parse(lines); err != nil {
		return nil, fmt.Errorf("ipt.parse: %s", err)
	}

	return ipt, nil
}

func (ipt *IPTables) parse(lines []string) error {
	table := ""

	for _, line := range lines {
		switch {
		// ignore empty lines and comments
		case line == "" || strings.HasPrefix(line, "#"):
			break
		// table
		case strings.HasPrefix(line, "*"):
			table = strings.TrimPrefix(line, "*")
			if _, found := ipt.tables[table]; found {
				return fmt.Errorf("table already exists: %s", table)
			}
			ipt.tables[table] = &Table{
				name:   table,
				chains: make(map[string]*Chain),
			}
		// chain
		case strings.HasPrefix(line, ":"):
			chainInfo := strings.Split(strings.TrimPrefix(line, ":"), " ")
			name := chainInfo[0]
			accept := chainInfo[1] == "ACCEPT"
			if _, found := ipt.tables[table].chains[name]; found {
				return fmt.Errorf("chain already exists: %s", name)
			}
			ipt.tables[table].chains[name] =
				&Chain{
					name:                  name,
					isDefaultPolicyAccept: accept,
					rules:                 make([]*Rule, 0),
				}
		// COMMIT ends table definition
		case line == "COMMIT":
			table = ""
		default:
			// rule
			if m := ruleRegexp.FindStringSubmatch(line); m != nil {
				pktCount, err := strconv.Atoi(m[1])
				if err != nil {
					return fmt.Errorf("cannot convert pkt count %s: %s", m[1], err)
				}
				bytesCount, err := strconv.Atoi(m[2])
				if err != nil {
					return fmt.Errorf("cannot convert bytes count %s: %s", m[2], err)
				}
				chain := m[3]
				args := m[4]
				target := m[5]
				ipt.tables[table].chains[chain].rules =
					append(ipt.tables[table].chains[chain].rules,
						&Rule{
							pktCount:   pktCount,
							bytesCount: bytesCount,
							args:       args,
							target:     target,
						})
			} else {
				return fmt.Errorf("invalid line: %s", line)
			}
		}
	}

	return nil
}
