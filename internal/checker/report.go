package checker

import (
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"
)

// WriteJSON serializes results as a JSON array, one object per certificate.
func WriteJSON(w io.Writer, results []Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(results)
}

// WriteTable renders a padded, human-readable table sorted soonest-expiry-first.
func WriteTable(w io.Writer, results []Result) error {
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "DOMAIN\tREGION\tTYPE\tDAYS LEFT\tRENEWABLE\tIN USE\tEXPIRES\tREASON")
	for _, r := range results {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			r.Domain,
			r.Region,
			typeShort(r),
			daysLeftStr(r),
			yesNo(r.Renewable),
			yesNo(r.InUse),
			expiresStr(r),
			r.Reason,
		)
	}
	return tw.Flush()
}

func daysLeftStr(r Result) string {
	if r.DaysLeft == nil {
		return "-"
	}
	return fmt.Sprintf("%d", *r.DaysLeft)
}

func expiresStr(r Result) string {
	if r.NotAfter == "" {
		return "-"
	}
	// Trim to the date portion for a compact column.
	if len(r.NotAfter) >= 10 {
		return r.NotAfter[:10]
	}
	return r.NotAfter
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// typeShort renders the ACM certificate type in a narrow column.
func typeShort(r Result) string {
	switch r.certType {
	case "AMAZON_ISSUED":
		return "amazon"
	case "IMPORTED":
		return "imported"
	case "":
		return "-"
	default:
		return r.certType
	}
}
