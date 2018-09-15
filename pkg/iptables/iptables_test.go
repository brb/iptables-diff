package iptables

import (
	"encoding/json"
	"reflect"
	"testing"

	r "github.com/stretchr/testify/require"
)

func TestNewFromIPTablesSave(t *testing.T) {
	ipt, err := NewFromIPTablesSave(output1)
	r.NoError(t, err)

	// Should contain two tables
	k := keys(ipt.tables)
	r.Contains(t, k, "filter")
	r.Contains(t, k, "nat")
	r.Equal(t, 2, len(k))

	// "nat" table should contain 5 chains
	k = keys(ipt.tables["nat"].chains)
	r.Equal(t, 5, len(k))
	for _, c := range []string{"PREROUTING", "INPUT", "OUTPUT", "POSTROUTING", "DOCKER"} {
		r.Contains(t, k, c)
	}

	// "nat/PREROUTING" should contain one rule
	rules := ipt.tables["nat"].chains["PREROUTING"].rules
	r.Equal(t, 1, len(rules))
	rule := rules[0]
	r.Equal(t, 5, rule.pktCount)
	r.Equal(t, 63, rule.bytesCount)
	r.Equal(t, "-m addrtype --dst-type LOCAL", rule.args)
	r.Equal(t, "DOCKER", rule.target)
}

func TestDiff(t *testing.T) {
	ipt, err := NewFromIPTablesSave(output1)
	r.NoError(t, err)
	later, err := NewFromIPTablesSave(output2)
	r.NoError(t, err)

	diff := ipt.Diff(later)
	// Should contain only one table
	r.Len(t, diff.tables, 1)
	// Should contain only two chains ("DOCKER" and "PREROUTING")
	r.Len(t, diff.tables["nat"].chains, 2)

	rule1 := diff.tables["nat"].chains["DOCKER"].rules[0]
	rule2 := diff.tables["nat"].chains["DOCKER"].rules[1]
	rule3 := diff.tables["nat"].chains["PREROUTING"].rules[0]
	r.Equal(t, NewRule("nat", "DOCKER", "-i docker1", "RETURN", 5, 9), rule1)
	r.Equal(t, NewRule("nat", "DOCKER", "-i docker2", "RETURN", 0, 0), rule2)
	r.Equal(t, NewRule("nat", "PREROUTING", "-m addrtype --dst-type LOCAL", "DOCKER", 1, 2), rule3)
}

func TestMarshalJSON(t *testing.T) {
	ipt, err := NewFromIPTablesSave(output1)
	r.NoError(t, err)
	obj, err := ipt.MarshalJSON()
	r.NoError(t, err)
	var tmp *IPTables
	err = json.Unmarshal(obj, &tmp)
	r.NoError(t, err)
}

func keys(m interface{}) []string {
	keysValue := reflect.ValueOf(m).MapKeys()
	keysString := make([]string, len(keysValue))
	i := 0

	for _, k := range keysValue {
		keysString[i] = k.String()
		i++
	}

	return keysString
}

const (
	output1 = `
# Generated by iptables-save v1.6.2 on Fri Sep  7 21:15:01 2018
*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:DOCKER - [0:0]
[5:63] -A PREROUTING -m addrtype --dst-type LOCAL -j DOCKER
[0:0] -A OUTPUT ! -d 127.0.0.0/8 -m addrtype --dst-type LOCAL -j DOCKER
[0:0] -A POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE
[0:0] -A POSTROUTING -s 172.18.0.0/16 ! -o br-ebbb6a48ec74 -j MASQUERADE
[1:2] -A DOCKER -i docker0 -j RETURN
[0:0] -A DOCKER -i br-ebbb6a48ec74 -j RETURN
COMMIT
# Completed on Fri Sep  7 21:15:01 2018
# Generated by iptables-save v1.6.2 on Fri Sep  7 21:15:01 2018
*filter
:INPUT ACCEPT [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:DOCKER - [0:0]
:DOCKER-ISOLATION-STAGE-1 - [0:0]
:DOCKER-ISOLATION-STAGE-2 - [0:0]
:DOCKER-USER - [0:0]
[0:0] -A FORWARD -j DOCKER-USER
[0:0] -A FORWARD -j DOCKER-ISOLATION-STAGE-1
[0:0] -A FORWARD -o docker0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
[0:0] -A FORWARD -o docker0 -j DOCKER
[0:0] -A FORWARD -i docker0 ! -o docker0 -j ACCEPT
[0:0] -A FORWARD -i docker0 -o docker0 -j ACCEPT
[0:0] -A FORWARD -o br-ebbb6a48ec74 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
[0:0] -A FORWARD -o br-ebbb6a48ec74 -j DOCKER
[0:0] -A FORWARD -i br-ebbb6a48ec74 ! -o br-ebbb6a48ec74 -j ACCEPT
[0:0] -A FORWARD -i br-ebbb6a48ec74 -o br-ebbb6a48ec74 -j ACCEPT
[0:0] -A DOCKER-ISOLATION-STAGE-1 -i docker0 ! -o docker0 -j DOCKER-ISOLATION-STAGE-2
[0:0] -A DOCKER-ISOLATION-STAGE-1 -i br-ebbb6a48ec74 ! -o br-ebbb6a48ec74 -j DOCKER-ISOLATION-STAGE-2
[0:0] -A DOCKER-ISOLATION-STAGE-1 -j RETURN
[0:0] -A DOCKER-ISOLATION-STAGE-2 -o docker0 -j DROP
[0:0] -A DOCKER-ISOLATION-STAGE-2 -o br-ebbb6a48ec74 -j DROP
[0:0] -A DOCKER-ISOLATION-STAGE-2 -j RETURN
[0:0] -A DOCKER-USER -j RETURN
COMMIT
# Completed on Fri Sep  7 21:15:01 2018
`
	output2 = `
# Generated by iptables-save v1.6.2 on Fri Sep  7 21:15:01 2018
*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:DOCKER - [0:0]
[6:65] -A PREROUTING -m addrtype --dst-type LOCAL -j DOCKER
[0:0] -A OUTPUT ! -d 127.0.0.0/8 -m addrtype --dst-type LOCAL -j DOCKER
[0:0] -A POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE
[0:0] -A POSTROUTING -s 172.18.0.0/16 ! -o br-ebbb6a48ec74 -j MASQUERADE
[1:2] -A DOCKER -i docker0 -j RETURN
[5:9] -A DOCKER -i docker1 -j RETURN
[0:0] -A DOCKER -i docker2 -j RETURN
[0:0] -A DOCKER -i br-ebbb6a48ec74 -j RETURN
COMMIT
# Completed on Fri Sep  7 21:15:01 2018
# Generated by iptables-save v1.6.2 on Fri Sep  7 21:15:01 2018
*filter
:INPUT ACCEPT [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:DOCKER - [0:0]
:DOCKER-ISOLATION-STAGE-1 - [0:0]
:DOCKER-ISOLATION-STAGE-2 - [0:0]
:DOCKER-USER - [0:0]
[0:0] -A FORWARD -j DOCKER-USER
[0:0] -A FORWARD -j DOCKER-ISOLATION-STAGE-1
[0:0] -A FORWARD -o docker0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
[0:0] -A FORWARD -o docker0 -j DOCKER
[0:0] -A FORWARD -i docker0 ! -o docker0 -j ACCEPT
[0:0] -A FORWARD -i docker0 -o docker0 -j ACCEPT
[0:0] -A FORWARD -o br-ebbb6a48ec74 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
[0:0] -A FORWARD -o br-ebbb6a48ec74 -j DOCKER
[0:0] -A FORWARD -i br-ebbb6a48ec74 ! -o br-ebbb6a48ec74 -j ACCEPT
[0:0] -A FORWARD -i br-ebbb6a48ec74 -o br-ebbb6a48ec74 -j ACCEPT
[0:0] -A DOCKER-ISOLATION-STAGE-1 -i docker0 ! -o docker0 -j DOCKER-ISOLATION-STAGE-2
[0:0] -A DOCKER-ISOLATION-STAGE-1 -i br-ebbb6a48ec74 ! -o br-ebbb6a48ec74 -j DOCKER-ISOLATION-STAGE-2
[0:0] -A DOCKER-ISOLATION-STAGE-1 -j RETURN
[0:0] -A DOCKER-ISOLATION-STAGE-2 -o docker0 -j DROP
[0:0] -A DOCKER-ISOLATION-STAGE-2 -o br-ebbb6a48ec74 -j DROP
[0:0] -A DOCKER-ISOLATION-STAGE-2 -j RETURN
[0:0] -A DOCKER-USER -j RETURN
COMMIT
# Completed on Fri Sep  7 21:15:01 2018
`
)
