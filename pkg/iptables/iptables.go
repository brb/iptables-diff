package iptables

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	u "github.com/satori/go.uuid"
)

var (
	ruleRegexp = regexp.MustCompile(`^\[(?P<cnt>\d+):(?P<byte>\d+)\] -A (?P<chain>[^ ]+) (.*?) ?-j (?P<target>.*)$`)
)

type IPTables struct {
	tables map[string]*Table
}

type Table struct {
	uid    u.UUID
	name   string
	chains map[string]*Chain
}

type Chain struct {
	uid                   u.UUID
	name                  string
	isDefaultPolicyAccept bool
	rules                 []*Rule
}

type Rule struct {
	uid        u.UUID
	args       string
	target     string
	pktCount   int
	bytesCount int
}

func New() *IPTables {
	return &IPTables{
		tables: make(map[string]*Table),
	}
}

func NewFromIPTablesSave(output string) (*IPTables, error) {
	ipt := New()

	lines := strings.Split(output, "\n")
	if err := ipt.parse(lines); err != nil {
		return nil, fmt.Errorf("ipt.parse: %s", err)
	}

	return ipt, nil
}

func NewTable(name string) *Table {
	return &Table{
		uid:    uuid(name),
		name:   name,
		chains: make(map[string]*Chain),
	}
}

func NewChain(table, name string, accept bool) *Chain {
	return &Chain{
		uid:                   uuid(table + name),
		name:                  name,
		isDefaultPolicyAccept: accept,
		rules:                 make([]*Rule, 0),
	}
}

func NewRule(table, chain, args, target string, pktCount, bytesCount int) *Rule {
	return &Rule{
		uid:        uuid(table + chain + args + target),
		pktCount:   pktCount,
		bytesCount: bytesCount,
		args:       args,
		target:     target,
	}
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
			ipt.tables[table] = NewTable(table)
		// chain
		case strings.HasPrefix(line, ":"):
			chainInfo := strings.Split(strings.TrimPrefix(line, ":"), " ")
			name := chainInfo[0]
			accept := chainInfo[1] == "ACCEPT"
			if _, found := ipt.tables[table].chains[name]; found {
				return fmt.Errorf("chain already exists: %s", name)
			}
			ipt.tables[table].chains[name] = NewChain(table, name, accept)
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
						NewRule(table, chain, args, target, pktCount, bytesCount))
			} else {
				return fmt.Errorf("invalid line: %s", line)
			}
		}
	}

	return nil
}

func (ipt *IPTables) Diff(later *IPTables) *IPTables {
	diff := New()

	for tableName, table := range later.tables {
		diff.tables[tableName] = NewTable(tableName)

		for chainName, chain := range table.chains {
			diff.tables[tableName].chains[chainName] =
				NewChain(tableName, chainName, chain.isDefaultPolicyAccept)

			if _, found := ipt.tables[tableName].chains[chainName]; !found {
				rules := diff.tables[tableName].chains[chainName].rules
				rules = make([]*Rule, len(chain.rules))
				copy(rules, chain.rules)
				continue
			}

			rules := make([]*Rule, 0)
			for _, rule := range chain.rules {
				// TODO(brb) find by uid
				r := ipt.FindRule(tableName, chainName, rule.args, rule.target)

				if r == nil {
					rules = append(rules, rule)
					continue
				}

				if r.pktCount == rule.pktCount {
					continue
				}

				if r.pktCount > rule.pktCount {
					// TODO(brb): can happen if counters have been reset before obtaining `later`
					panic("NYI")
				}

				rules = append(rules,
					NewRule(tableName, chainName, rule.args, rule.target,
						rule.pktCount-r.pktCount, rule.bytesCount-r.bytesCount))
			}
			if len(rules) == 0 {
				delete(diff.tables[tableName].chains, chainName)
			} else {
				diff.tables[tableName].chains[chainName].rules = rules
			}
		}

		if len(diff.tables[tableName].chains) == 0 {
			delete(diff.tables, tableName)
		}

	}

	return diff
}

func (ipt *IPTables) FindRule(table, chain, args, target string) *Rule {
	tab, found := ipt.tables[table]
	if !found {
		return nil
	}

	ch, found := tab.chains[chain]
	if !found {
		return nil
	}

	for _, rule := range ch.rules {
		if rule.args == args && rule.target == target {
			return rule
		}
	}

	return nil
}

func uuid(name string) u.UUID {
	var null u.UUID
	return u.NewV5(null, name)
}
