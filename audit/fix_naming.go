package audit

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

// ToUpperSnakeCase converts a string (camelCase, PascalCase, kebab-case, snake_case, etc.) to UPPER_SNAKE_CASE.
func ToUpperSnakeCase(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}

	var runes []rune
	rList := []rune(s)

	for i, r := range rList {
		if i > 0 {
			prev := rList[i-1]
			// lowercase/digit followed by uppercase -> insert underscore (camelCase -> camel_Case)
			if (unicode.IsLower(prev) || unicode.IsDigit(prev)) && unicode.IsUpper(r) {
				runes = append(runes, '_')
			} else if i+1 < len(rList) && unicode.IsUpper(prev) && unicode.IsUpper(r) && unicode.IsLower(rList[i+1]) {
				// consecutive uppercase followed by lowercase (e.g. HTTPResponse -> HTTP_Response)
				runes = append(runes, '_')
			} else if prev == '-' || prev == '.' || prev == ' ' || prev == '/' || prev == '\\' {
				runes = append(runes, '_')
			}
		}

		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			runes = append(runes, unicode.ToUpper(r))
		} else if r == '_' {
			runes = append(runes, '_')
		}
	}

	res := string(runes)
	// Replace multiple consecutive underscores with single underscore
	reUnderscores := regexp.MustCompile(`_+`)
	res = reUnderscores.ReplaceAllString(res, "_")
	res = strings.Trim(res, "_")

	// Ensure it doesn't start with a digit
	if len(res) > 0 && unicode.IsDigit(rune(res[0])) {
		res = "ENV_" + res
	}

	return res
}

// ExtractVarNameFromLine tries to extract a variable name, dict/object key, or parameter name on the line where secret appears.
func ExtractVarNameFromLine(line, rawSecret string, lang LanguageType) string {
	idx := strings.Index(line, rawSecret)
	if idx == -1 {
		return ""
	}

	prefix := line[:idx]

	if lang == LangDotenv {
		// Example: DB_PASS=supersecret... or "PORT"=3000
		if eqIdx := strings.Index(line, "="); eqIdx != -1 && eqIdx < idx {
			key := strings.TrimSpace(line[:eqIdx])
			key = strings.Trim(key, `"'`)
			return ToUpperSnakeCase(key)
		}
		return ""
	}

	// Clean trailing quotes or spaces before assignment/colon (e.g. `API_KEY = "` -> `API_KEY =`)
	cleanPrefix := strings.TrimRight(prefix, " \t\"'`")

	// 1. Check for dict / JSON / object property with quotes:
	// e.g. "db_password": ..., 'api_key': ...
	dictPropRegex := regexp.MustCompile(`["']([a-zA-Z0-9_\-\.]+)["']\s*:\s*$`)
	if m := dictPropRegex.FindStringSubmatch(cleanPrefix); len(m) > 1 {
		return ToUpperSnakeCase(m[1])
	}

	// 2. Check for unquoted object key:
	// e.g. db_password: ..., apiKey: ...
	unquotedPropRegex := regexp.MustCompile(`([a-zA-Z0-9_\-\.]+)\s*:\s*$`)
	if m := unquotedPropRegex.FindStringSubmatch(cleanPrefix); len(m) > 1 {
		return ToUpperSnakeCase(m[1])
	}

	// 3. Check for assignment:
	// e.g. const API_KEY = ..., let stripeKey = ..., api_key = ...
	assignRegex := regexp.MustCompile(`(?:(?:const|let|var)\s+)?([a-zA-Z0-9_\-\.]+)\s*=\s*$`)
	if m := assignRegex.FindStringSubmatch(cleanPrefix); len(m) > 1 {
		return ToUpperSnakeCase(m[1])
	}

	// 4. Check for keyword argument / named parameter:
	// e.g. func(api_key=..., token=...)
	kwargRegex := regexp.MustCompile(`(?:[\(,]\s*)([a-zA-Z0-9_\-\.]+)\s*=\s*$`)
	if m := kwargRegex.FindStringSubmatch(cleanPrefix); len(m) > 1 {
		return ToUpperSnakeCase(m[1])
	}

	return ""
}

// DeriveSmartEnvVarName extracts name from line or falls back to ruleID, guaranteeing uniqueness in file.
func DeriveSmartEnvVarName(line, rawSecret, ruleID string, lang LanguageType, existing map[string]bool) string {
	name := ExtractVarNameFromLine(line, rawSecret, lang)
	if name == "" {
		name = ToUpperSnakeCase(ruleID)
	}
	if name == "" {
		name = "SECRET_TOKEN"
	}

	candidate := name
	counter := 2
	for existing[candidate] {
		candidate = fmt.Sprintf("%s_%d", name, counter)
		counter++
	}
	existing[candidate] = true
	return candidate
}
