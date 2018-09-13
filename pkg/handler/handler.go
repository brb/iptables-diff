package handler

import (
	"encoding/json"
	"net/http"
	"os/exec"

	"github.com/brb/iptables-diff/pkg/iptables"
)

type Handler struct {
	before *iptables.IPTables
	after  *iptables.IPTables
}

func New() *Handler {
	return &Handler{}
}

func (h *Handler) HandleGetIPTables(w http.ResponseWriter, r *http.Request) {
	cmd := exec.Command("iptables-save", "-c")
	out, err := cmd.Output()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	ipt, err := iptables.NewFromIPTablesSave(string(out))
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ipt)
}
