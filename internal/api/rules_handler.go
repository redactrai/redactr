package api

import (
	"encoding/json"
	"net/http"

	"github.com/rakeshguha/redactr/internal/config"
	"github.com/rakeshguha/redactr/internal/rules"
)

type rulesResponseTier struct {
	ID           string `json:"id"`
	Label        string `json:"label"`
	Default      bool   `json:"default"`
	WarningLevel string `json:"warning_level"`
}

type rulesResponseGroup struct {
	ID    string   `json:"id"`
	Label string   `json:"label"`
	Tier  string   `json:"tier"`
	Rules []string `json:"rules"`
}

type rulesResponseRule struct {
	ID       string `json:"id"`
	Label    string `json:"label"`
	Describe string `json:"describe"`
	Group    string `json:"group"`
	Tier     string `json:"tier"`
	Layer    string `json:"layer"`
	Default  bool   `json:"default"`
	Enabled  bool   `json:"enabled"`
}

func (s *Server) handleGetRules(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfgMgr.Get()
	effective := rules.Effective(cfg.Scanning.Rules)

	resp := struct {
		Tiers  []rulesResponseTier  `json:"tiers"`
		Groups []rulesResponseGroup `json:"groups"`
		Rules  []rulesResponseRule  `json:"rules"`
	}{
		Tiers: []rulesResponseTier{
			{ID: "always_on", Label: "Always On", Default: true, WarningLevel: "modal_and_banner"},
			{ID: "good_to_have", Label: "Good to Have", Default: true, WarningLevel: "inline_confirm"},
			{ID: "to_be_safer", Label: "To Be Safer", Default: false, WarningLevel: "silent"},
		},
	}
	for _, g := range rules.AllGroups() {
		resp.Groups = append(resp.Groups, rulesResponseGroup{
			ID: g.ID, Label: g.Label, Tier: g.Tier.String(), Rules: g.Rules,
		})
	}
	for _, r := range rules.AllRules() {
		resp.Rules = append(resp.Rules, rulesResponseRule{
			ID:       r.ID,
			Label:    r.Label,
			Describe: r.Describe,
			Group:    r.Group,
			Tier:     r.Tier.String(),
			Layer:    r.Layer,
			Default:  rules.ResolveDefault(r.Tier),
			Enabled:  effective[r.ID],
		})
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		// Already wrote some bytes; just return.
		return
	}
}

func (s *Server) handlePutRules(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Rules map[string]bool `json:"rules"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	if body.Rules == nil {
		body.Rules = map[string]bool{}
	}

	var unknown []string
	for id := range body.Rules {
		if !rules.IsKnown(id) {
			unknown = append(unknown, id)
		}
	}
	if len(unknown) > 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error":    "unknown rule_ids",
			"rule_ids": unknown,
		})
		return
	}

	normalised := rules.Normalise(body.Rules)
	if err := s.cfgMgr.Update(func(c *config.Config) {
		c.Scanning.Rules = normalised
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "save failed: "+err.Error())
		return
	}

	if s.coordinator != nil {
		cfg := s.cfgMgr.Get()
		eff := rules.Effective(cfg.Scanning.Rules)
		exts, contentPatterns := rules.FileBlockExtensions(
			cfg.FileBlocking.BlockedExtensions,
			eff,
			cfg.FileBlocking.ContentPatternsEnabled,
		)
		s.coordinator.Reconfigure(
			func(id string) bool { return eff[id] },
			exts,
			contentPatterns,
		)
	}

	writeJSON(w, map[string]any{"ok": true})
}
