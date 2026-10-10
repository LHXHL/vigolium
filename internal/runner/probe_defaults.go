package runner

// probeStealth is the spidering.stealth mode module browser confirmations run
// with ("" = auto when no settings are loaded), so a confirmation sees the
// page the crawl saw.
func (r *Runner) probeStealth() string {
	if r.settings == nil {
		return ""
	}
	return r.settings.Spidering.Stealth
}
