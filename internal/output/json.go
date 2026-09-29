package output

import (
	"encoding/json"
	"io"

	"github.com/secorvia/frontdoor/internal/model"
)

// JSON writes the full machine-readable result.
func JSON(w io.Writer, res *model.Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(res)
}
