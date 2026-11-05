package approve

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jaekwon/autopatch/guard"
)

// TestPrintMemo prints guard one's Yes memo when PRINT_MEMO is set; it
// makes the fixture that TestVerifyYes checks.
func TestPrintMemo(t *testing.T) {
	if os.Getenv("PRINT_MEMO") == "" {
		t.Skip("set PRINT_MEMO to print the fixture's memo")
	}
	b, err := os.ReadFile("../guard/testdata/cve-2026-98432.json")
	if err != nil {
		t.Fatal(err)
	}
	g, err := guard.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	m, err := MemoYes(g, Yes{Hash: g.Hash(), Tiers: []string{"A"}, Until: time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC), Mode: "undo"})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Print(m)
}
