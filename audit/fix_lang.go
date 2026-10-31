package audit

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

type LanguageType string

const (
	LangPython     LanguageType = "python"
	LangJavaScript LanguageType = "javascript"
	LangDotenv     LanguageType = "dotenv"
	LangUnknown    LanguageType = "unknown"
)

func DetectLanguage(filePath string) LanguageType {
	base := filepath.Base(filePath)
	if base == ".env" || strings.HasPrefix(base, ".env.") {
		// exclude templates or examples
		lower := strings.ToLower(base)
		if strings.Contains(lower, "example") || strings.Contains(lower, "sample") || strings.Contains(lower, "template") {
			return LangUnknown
		}
		return LangDotenv
	}
	ext := strings.ToLower(filepath.Ext(filePath))
	switch ext {
	case ".py":
		return LangPython
	case ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs":
		return LangJavaScript
	default:
		return LangUnknown
	}
}

// DeriveEnvVarName returns a clean, unique environment variable name.
// e.g. ruleID "aws-access-key", existing vars in file.
func DeriveEnvVarName(ruleID string, existing map[string]bool) string {
	clean := strings.ToUpper(ruleID)
	reg := regexp.MustCompile(`[^A-Z0-9]+`)
	clean = reg.ReplaceAllString(clean, "_")
	clean = strings.Trim(clean, "_")
	if clean == "" {
		clean = "SECRET_TOKEN"
	}

	name := clean
	counter := 1
	for existing[name] {
		counter++
		name = fmt.Sprintf("%s_%d", clean, counter)
	}
	existing[name] = true
	return name
}

// PatchResult contains the transformed line/content and metadata.
type PatchResult struct {
	PatchedLine   string
	AddedImport   bool
	AddedLines    []string
	SkippedReason string
}

// PatchPythonLine replaces the string literal containing secret with os.environ["VAR"]
func PatchPythonLine(line, rawSecret, envVar string) (string, string) {
	idx := strings.Index(line, rawSecret)
	if idx == -1 {
		return line, "secret not found on line"
	}

	// Check if secret is enclosed in quotes
	// Look backwards for quote
	quoteChar := byte(0)
	quoteStart := -1
	for i := idx - 1; i >= 0; i-- {
		if line[i] == '"' || line[i] == '\'' {
			quoteChar = line[i]
			quoteStart = i
			break
		}
		if line[i] != ' ' && line[i] != '\t' && line[i] != '=' && line[i] != '(' && line[i] != '[' && line[i] != '{' && line[i] != ':' && line[i] != ',' {
			// Embedded in non-quote or identifier prefix
			break
		}
	}

	if quoteStart == -1 {
		return line, "embedded in a larger string"
	}

	quoteEnd := -1
	secretEnd := idx + len(rawSecret)
	if secretEnd < len(line) && line[secretEnd] == quoteChar {
		quoteEnd = secretEnd
	}

	// Check if there is extra text between quoteStart and idx, or between secretEnd and quoteEnd
	if quoteStart != -1 && quoteEnd != -1 {
		// Literal is line[quoteStart : quoteEnd+1]
		// Verify nothing else inside the literal:
		inside := line[quoteStart+1 : quoteEnd]
		if inside != rawSecret {
			return line, "embedded in a larger string"
		}

		replacement := fmt.Sprintf(`os.environ["%s"]`, envVar)
		return line[:quoteStart] + replacement + line[quoteEnd+1:], ""
	}

	return line, "embedded in a larger string"
}

// PatchJSLine replaces the string literal containing secret with process.env.VAR
func PatchJSLine(line, rawSecret, envVar string) (string, string) {
	idx := strings.Index(line, rawSecret)
	if idx == -1 {
		return line, "secret not found on line"
	}

	quoteChar := byte(0)
	quoteStart := -1
	for i := idx - 1; i >= 0; i-- {
		if line[i] == '"' || line[i] == '\'' || line[i] == '`' {
			quoteChar = line[i]
			quoteStart = i
			break
		}
		if line[i] != ' ' && line[i] != '\t' && line[i] != '=' && line[i] != '(' && line[i] != '[' && line[i] != '{' && line[i] != ':' && line[i] != ',' {
			break
		}
	}

	if quoteStart == -1 {
		return line, "embedded in a larger string"
	}

	quoteEnd := -1
	secretEnd := idx + len(rawSecret)
	if secretEnd < len(line) && line[secretEnd] == quoteChar {
		quoteEnd = secretEnd
	}

	if quoteStart != -1 && quoteEnd != -1 {
		inside := line[quoteStart+1 : quoteEnd]
		if inside != rawSecret {
			return line, "embedded in a larger string"
		}

		replacement := fmt.Sprintf("process.env.%s", envVar)
		return line[:quoteStart] + replacement + line[quoteEnd+1:], ""
	}

	return line, "embedded in a larger string"
}

// InsertPythonImportOS adds 'import os' after shebang, docstrings, or encoding, and before other imports
func InsertPythonImportOS(lines []string) []string {
	// Check if already imports os
	for _, l := range lines {
		trimmed := strings.TrimSpace(l)
		if trimmed == "import os" || strings.HasPrefix(trimmed, "import os,") || strings.HasPrefix(trimmed, "import os ") || strings.HasPrefix(trimmed, "from os ") {
			return lines
		}
	}

	insertIdx := 0
	inDocstring := false
	docstringDelim := ""

	for i, l := range lines {
		trimmed := strings.TrimSpace(l)

		if inDocstring {
			if strings.Contains(trimmed, docstringDelim) {
				inDocstring = false
				insertIdx = i + 1
			}
			continue
		}

		if strings.HasPrefix(trimmed, "#") {
			insertIdx = i + 1
			continue
		}

		if strings.HasPrefix(trimmed, `"""`) || strings.HasPrefix(trimmed, `'''`) {
			delim := trimmed[:3]
			// check if single line docstring
			rest := trimmed[3:]
			if strings.Contains(rest, delim) {
				insertIdx = i + 1
				continue
			}
			inDocstring = true
			docstringDelim = delim
			continue
		}

		if trimmed == "" {
			insertIdx = i + 1
			continue
		}

		// First real code statement
		insertIdx = i
		break
	}

	// Insert "import os" at insertIdx
	res := make([]string, 0, len(lines)+1)
	res = append(res, lines[:insertIdx]...)
	res = append(res, "import os")
	res = append(res, lines[insertIdx:]...)
	return res
}

