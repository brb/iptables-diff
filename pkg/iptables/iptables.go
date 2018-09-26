package iptables

import (
	"bytes"
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
	Tables map[string]*Table `json:"tables,omitempty"`
}

type Table struct {
	UID    u.UUID            `json:"uid,omitempty"`
	Name   string            `json:"name,omitempty"`
	Chains map[string]*Chain `json:"chains,omitempty"`
}

type Chain struct {
	UID                   u.UUID  `json:"uid,omitempty"`
	Name                  string  `json:"name,omitempty"`
	IsDefaultPolicyAccept bool    `json:accept,omitempty"`
	Rules                 []*Rule `json:rules,omitempty"`
}

type Rule struct {
	UID        u.UUID `json:"uid,omitempty"`
	Args       string `json:"args,omitempty"`
	Target     string `json:"target,omitempty"`
	PktCount   int    `json:"pkt_count,omitempty"`
	BytesCount int    `json:"bytes_count,omitempty"`
}

func New() *IPTables {
	return &IPTables{
		Tables: make(map[string]*Table),
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
		UID:    uuid(name),
		Name:   name,
		Chains: make(map[string]*Chain),
	}
}

func NewChain(table, name string, accept bool) *Chain {
	return &Chain{
		UID:                   uuid(table + name),
		Name:                  name,
		IsDefaultPolicyAccept: accept,
		Rules:                 make([]*Rule, 0),
	}
}

func NewRule(table, chain, args, target string, pktCount, bytesCount int) *Rule {
	return &Rule{
		UID:        uuid(table + chain + args + target),
		PktCount:   pktCount,
		BytesCount: bytesCount,
		Args:       args,
		Target:     target,
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
			if _, found := ipt.Tables[table]; found {
				return fmt.Errorf("table already exists: %s", table)
			}
			ipt.Tables[table] = NewTable(table)
		// chain
		case strings.HasPrefix(line, ":"):
			chainInfo := strings.Split(strings.TrimPrefix(line, ":"), " ")
			name := chainInfo[0]
			accept := chainInfo[1] == "ACCEPT"
			if _, found := ipt.Tables[table].Chains[name]; found {
				return fmt.Errorf("chain already exists: %s", name)
			}
			ipt.Tables[table].Chains[name] = NewChain(table, name, accept)
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
				ipt.Tables[table].Chains[chain].Rules =
					append(ipt.Tables[table].Chains[chain].Rules,
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

	for tableName, table := range later.Tables {
		diff.Tables[tableName] = NewTable(tableName)

		for chainName, chain := range table.Chains {
			diff.Tables[tableName].Chains[chainName] =
				NewChain(tableName, chainName, chain.IsDefaultPolicyAccept)

			if _, found := ipt.Tables[tableName].Chains[chainName]; !found {
				rules := diff.Tables[tableName].Chains[chainName].Rules
				rules = make([]*Rule, len(chain.Rules))
				copy(rules, chain.Rules)
				continue
			}

			rules := make([]*Rule, 0)
			for _, rule := range chain.Rules {
				// TODO(brb) find by uid
				r := ipt.FindRule(tableName, chainName, rule.Args, rule.Target)

				if r == nil {
					rules = append(rules, rule)
					continue
				}

				if r.PktCount == rule.PktCount {
					continue
				}

				if r.PktCount > rule.PktCount {
					// TODO(brb): can happen if counters have been reset before obtaining `later`
					panic("NYI")
				}

				rules = append(rules,
					NewRule(tableName, chainName, rule.Args, rule.Target,
						rule.PktCount-r.PktCount, rule.BytesCount-r.BytesCount))
			}
			if len(rules) == 0 {
				delete(diff.Tables[tableName].Chains, chainName)
			} else {
				diff.Tables[tableName].Chains[chainName].Rules = rules
			}
		}

		if len(diff.Tables[tableName].Chains) == 0 {
			delete(diff.Tables, tableName)
		}

	}

	return diff
}

func (ipt *IPTables) FindRule(table, chain, args, target string) *Rule {
	tab, found := ipt.Tables[table]
	if !found {
		return nil
	}

	ch, found := tab.Chains[chain]
	if !found {
		return nil
	}

	for _, rule := range ch.Rules {
		if rule.Args == args && rule.Target == target {
			return rule
		}
	}

	return nil
}

func uuid(name string) u.UUID {
	var null u.UUID
	return u.NewV5(null, name)
}
