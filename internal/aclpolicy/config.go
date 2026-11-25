package aclpolicy

// LintConfig is durable, reviewable configuration for policy lint checks.
type LintConfig struct {
	Checks LintChecksConfig `json:"checks"`
}

// LintChecksConfig contains configuration keyed by stable lint finding ID.
type LintChecksConfig struct {
	BroadRuleUntested BroadRuleUntestedConfig `json:"broad-rule-untested"`
}

// BroadRuleUntestedConfig configures the broad-rule-untested advisory.
type BroadRuleUntestedConfig struct {
	AllowBroad []string `json:"allowBroad,omitempty"`
}

// LoadLintConfig reads a JSON or HuJSON lint config. Unknown fields are
// rejected so a misspelled exclusion cannot silently look effective.
func LoadLintConfig(path string) (*LintConfig, error) { return Files{}.LoadLintConfig(path) }

// LoadLintConfig is the package-level LoadLintConfig under f's read limit.
func (f Files) LoadLintConfig(path string) (*LintConfig, error) {
	raw, err := f.ReadRaw(path)
	if err != nil {
		return nil, err
	}
	var config LintConfig
	if err = decodeHuJSON(path, raw, "a tsacl lint config", &config); err != nil {
		return nil, err
	}
	return &config, nil
}
