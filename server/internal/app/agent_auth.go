package app

import (
	"net/http"
)

// agentMachineCode is a compatibility wrapper for callers that only need a
// boolean authorization result. All Agent endpoints share one validator.
func (a *App) agentMachineCode(r *http.Request) (string, bool) {
	code, err := a.agentMachineFromRequest(r)
	return code, err == nil
}
