package cmd

import (
	"flag"
	"os"
	"strings"
)

func flagPassed(fs *flag.FlagSet, name string) bool {
	passed := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			passed = true
		}
	})
	return passed
}

func resolveOptionalString(fs *flag.FlagSet, flagName string, value *string, envName string) *string {
	if flagPassed(fs, flagName) {
		v := *value
		return &v
	}
	if v, ok := os.LookupEnv(envName); ok {
		return &v
	}
	return nil
}

func resolveString(fs *flag.FlagSet, flagName string, value *string, envName string) string {
	if flagPassed(fs, flagName) {
		return *value
	}
	if v, ok := os.LookupEnv(envName); ok {
		return v
	}
	return ""
}

func expandEnv(s string) string {
	const dollar = "\x00PORTREACH_LITERAL_DOLLAR\x00"
	s = strings.ReplaceAll(s, "$$", dollar)
	s = os.Expand(s, func(name string) string {
		return os.Getenv(name)
	})
	return strings.ReplaceAll(s, dollar, "$")
}

func expandOptionalEnv(s *string) *string {
	if s == nil {
		return nil
	}
	v := expandEnv(*s)
	return &v
}
