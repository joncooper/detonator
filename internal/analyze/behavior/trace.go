package behavior

import (
	"encoding/json"
	"fmt"
)

// Trace is the normalized dynamic-analysis behavior log emitted by the
// detonation sandbox (ossf/package-analysis format), validated on the burner
// against benign, synthetic, and real-malware samples. Each analysis phase
// (install / import / execute) records the files, sockets, commands, and DNS
// the package touched.
type Trace struct {
	Package  PackageInfo      `json:"Package"`
	Analysis map[string]Phase `json:"Analysis"`
}

// PackageInfo identifies the analyzed package (fields present vary by ecosystem).
type PackageInfo struct {
	Ecosystem string `json:"Ecosystem"`
	Name      string `json:"Name"`
	Version   string `json:"Version"`
}

// Phase is one activation point's captured behavior.
type Phase struct {
	Files    []FileOp    `json:"Files"`
	Sockets  []Socket    `json:"Sockets"`
	Commands []Command   `json:"Commands"`
	DNS      []DNSRecord `json:"DNS"`
	Status   string      `json:"Status"`
}

// FileOp is a file access with the operation flags the monitor observed.
type FileOp struct {
	Path   string `json:"Path"`
	Read   bool   `json:"Read"`
	Write  bool   `json:"Write"`
	Delete bool   `json:"Delete"`
}

// Socket is an outbound connection attempt (captured even when egress is denied).
type Socket struct {
	Address   string   `json:"Address"`
	Port      int      `json:"Port"`
	Hostnames []string `json:"Hostnames"`
}

// Command is a spawned process with its argv and environment.
type Command struct {
	Command     []string `json:"Command"`
	Environment []string `json:"Environment"`
}

// DNSRecord groups the queries observed in one DNS transaction.
type DNSRecord struct {
	Class   string     `json:"Class"`
	Queries []DNSQuery `json:"Queries"`
}

// DNSQuery is a single resolved hostname.
type DNSQuery struct {
	Hostname string   `json:"Hostname"`
	Types    []string `json:"Types"`
}

// ParseTrace decodes a package-analysis behavior log.
func ParseTrace(data []byte) (*Trace, error) {
	var t Trace
	if err := json.Unmarshal(data, &t); err != nil {
		return nil, fmt.Errorf("behavior: parse trace: %w", err)
	}
	if t.Analysis == nil {
		return nil, fmt.Errorf("behavior: trace has no Analysis section")
	}
	return &t, nil
}
