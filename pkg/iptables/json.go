package iptables

import (
	"bytes"
)

// { "tables": {
//     "nat": {
//       "chains": {
//		   "PREROUTING": {
//		     "rules": [ { "args": string, "target": string, "bytesCount": int, "pktCount": int} ]
//         }
//       }
//     }
//  }

func (ipt *IPTables) MarshalJSON() ([]byte, error) {
	buf := bytes.NewBufferString(`{"tables":{`)
	i := 0
	for tableName, table := range ipt.tables {
		// TODO(brb) handle errors from WriteString
		buf.WriteString(`"` + tableName + `":{"chains":{`)
		j := 0
		for chainName, chain := range table.chains {
			buf.WriteString(`"` + chainName + `":{"rules":[`)
			for i, rule := range chain.rules {
				buf.WriteString(`{"args":"` + rule.args + `","target":"` + rule.target +
					`","bytesCount":42,"pktCount":12}`)
				if i != len(chain.rules)-1 {
					buf.WriteString(`,`)
				}
			}
			buf.WriteString(`]}`)
			if j != len(table.chains)-1 {
				buf.WriteString(`,`)
			}
			j++
		}
		buf.WriteString(`}}`)
		if i != len(ipt.tables)-1 {
			buf.WriteString(`,`)
		}
		i++
	}
	buf.WriteString(`}}`)

	return buf.Bytes(), nil
}
