package bpfs

type BPFProgram interface {
	GetCompilationFlags() []string
	GetName() string
	GetSource() string
}

var BPFPrograms = make(map[string]BPFProgram)

func init() {
	BPFPrograms["Firewall"] = FirewallBpfImpl{}
	// add more programs in future?
}
