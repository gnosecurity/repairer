package lookout

import (
	"encoding/json"
	"fmt"
)

// KEV is CISA's list of known exploited flaws, by CVE id.
type KEV map[string]bool

// ParseKEV reads CISA's known exploited vulnerabilities JSON.
func ParseKEV(b []byte) (KEV, error) {
	var doc struct {
		Vulnerabilities []struct {
			CVE string `json:"cveID"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("lookout: CISA's list: %w", err)
	}
	k := KEV{}
	for _, v := range doc.Vulnerabilities {
		k[v.CVE] = true
	}
	return k, nil
}

// Mark sets Exploited on every finding whose flaw is on the list.
func (k KEV) Mark(fs []Finding) {
	for i := range fs {
		fs[i].Exploited = k[fs[i].Flaw]
	}
}
