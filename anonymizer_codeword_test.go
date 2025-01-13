package main

import (
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func TestAnonymizeDomains(t *testing.T) {
	a := NewAnonymizerCodeword("1")
	a.AddDomain("test")
	a.AddDomain("domain.com")
	a.AddDomain("www.company.com")
	testCases := []struct {
		input    string
		expected string
	}{
		{" abc.test ", " Domain22475.test "},
		{" abc.abc.test ", " Domain22475.Domain22475.test "},
		{" abc.def.test ", " Domain22475.Domain33968.test "},
		{" somedomain.com ", " somedomain.com "},
		{" ftp.company.com ", " ftp.company.com "},
		{" domain.com ", " domain.com "},
		{" www.domain.com ", " Domain07240.domain.com "},
	}
	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			actual := a.AnonymizeDomains(tc.input)
			if actual != tc.expected {
				t.Errorf("Expected %s, got %s", tc.expected, actual)
			}
		})
	}
}

func TestSQLite(t *testing.T) {
	// IterateOverAllData("/Users/michael/go/src/dsab/Agent/ds_agent.db")
}
