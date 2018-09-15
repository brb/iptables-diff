package iptables

import (
	"bytes"
	"strconv"
)

// { "tables": {
//     "nat": {
//       "uid": string,
//       "chains": {
//		   "PREROUTING": {
//         "uid": string,
//		     "rules": [ {
//           "uid": string,
//           "args": string,
//           "target": string,
//           "bytesCount": int,
//           "pktCount": int
//         } ]
//       }
//     }
//   }
// }

func (ipt *IPTables) MarshalJSON() ([]byte, error) {
	buf := bytes.NewBufferString(`{"tables":{`)
	i := 0
	for tableName, table := range ipt.tables {
		// TODO(brb) handle errors from WriteString
		buf.WriteString(`"` + tableName + `":{"uid":"` + table.uid.String() + `","chains":{`)
		j := 0
		for chainName, chain := range table.chains {
			buf.WriteString(`"` + chainName + `":{"uid":"` + chain.uid.String() + `","rules":[`)
			for i, rule := range chain.rules {
				bytesCount := strconv.Itoa(rule.bytesCount)
				pktCount := strconv.Itoa(rule.pktCount)
				buf.WriteString(`{"uid":"` + rule.uid.String() + `","args":"` + rule.args +
					`","target":"` + rule.target + `","bytesCount":` + bytesCount +
					`,"pktCount":` + pktCount + `}`)
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
