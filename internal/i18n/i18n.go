package i18n

import (
	"os/exec"
	"os"
	"strings"
	"runtime"
)

type Lang int

const (
	EN Lang = iota
	ID
)

var current Lang

func Init() {
	current = detectLanguage()
}

func InitWith(lang string) {
	switch strings.ToLower(lang) {
	case "id":
		current = ID
	case "en":
		current = EN
	default:
		current = detectLanguage()
	}
}

func Get() Lang {
	return current
}

func detectLanguage() Lang {
	if runtime.GOOS == "linux" {
		return detectLinuxLang()
	}
	if runtime.GOOS == "darwin" {
		return detectMacLang()
	}
	return EN
}

func detectLinuxLang() Lang {
	if lang := os.Getenv("LANGUAGE"); lang != "" {
		if isIndonesian(lang) {
			return ID
		}
	}
	if lc := os.Getenv("LC_ALL"); lc != "" {
		if isIndonesian(lc) {
			return ID
		}
	}
	if lang := os.Getenv("LANG"); lang != "" {
		if isIndonesian(lang) {
			return ID
		}
	}
	return EN
}

func detectMacLang() Lang {
	out, err := exec.Command("defaults", "read", "NSGlobalDomain", "AppleLocale").Output()
	if err != nil {
		return EN
	}
	locale := strings.TrimSpace(string(out))
	if isIndonesian(locale) {
		return ID
	}
	return EN
}

func isIndonesian(s string) bool {
	lower := strings.ToLower(s)
	return strings.HasPrefix(lower, "id") ||
		strings.Contains(lower, "_id") ||
		strings.Contains(lower, "-id")
}

func T(en, id string) string {
	if current == ID {
		return id
	}
	return en
}
