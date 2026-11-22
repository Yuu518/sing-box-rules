package lib

const (
	ActionAdd     Action = "add"
	ActionReplace Action = "replace"
	ActionRemove  Action = "remove"
	ActionOutput  Action = "output"

	RuleTypeDomain        RuleType = "domain"
	RuleTypeDomainSuffix  RuleType = "domain_suffix"
	RuleTypeDomainKeyword RuleType = "domain_keyword"
	RuleTypeDomainRegex   RuleType = "domain_regex"

	IPv4 IPType = "ipv4"
	IPv6 IPType = "ipv6"

	EntryKindAll     EntryKind = ""
	EntryKindDomain  EntryKind = "domain"
	EntryKindAdGuard EntryKind = "adguard"
	EntryKindIP      EntryKind = "ip"

	CaseRemoveRule  CaseRemove = 0
	CaseRemoveEntry CaseRemove = 1
)

var ActionsRegistry = map[Action]bool{
	ActionAdd:     true,
	ActionReplace: true,
	ActionRemove:  true,
	ActionOutput:  true,
}

type Action string

type RuleType string

type IPType string

type EntryKind string

type CaseRemove int

type Typer interface {
	GetType() string
}

type Actioner interface {
	GetAction() Action
}

type Descriptioner interface {
	GetDescription() string
}

type InputConverter interface {
	Typer
	Actioner
	Descriptioner
	Input(Container) (Container, error)
}

type OutputConverter interface {
	Typer
	Actioner
	Descriptioner
	Output(Container) error
}

type InputOption func(InputConverter)

type OutputOption func(OutputConverter)

type IgnoreIPOption func() IPType

func IgnoreIPv4() IPType {
	return IPv4
}

func IgnoreIPv6() IPType {
	return IPv6
}
