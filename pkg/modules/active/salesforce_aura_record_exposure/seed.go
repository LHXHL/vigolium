package salesforce_aura_record_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

// bogusObject is an object API name that cannot exist, used as the catch-all
// negative control (getItems for it must not return records).
const bogusObject = "Vigolium_Nonexistent_Probe__c"

// maxObjects bounds the getItems fan-out per host (standard set + harvested
// custom objects), so a community with hundreds of custom objects doesn't cause
// an unbounded request storm. Objects beyond the cap are skipped.
const maxObjects = 50

// standardObjects is the always-probed set of high-value standard SObjects.
var standardObjects = []string{
	"User", "Contact", "Lead", "Case", "CaseComment", "EmailMessage",
	"Account", "Note", "Document", "ContentDocument", "ContentVersion",
	"Attachment", "Opportunity", "Contract", "Campaign",
}

// criticalObjects hold the most sensitive personal / support data — a confirmed
// guest read of these is Critical; every other object (including custom __c) is
// reported High.
var criticalObjects = map[string]struct{}{
	"User":         {},
	"Contact":      {},
	"Lead":         {},
	"Case":         {},
	"CaseComment":  {},
	"EmailMessage": {},
	"Account":      {},
}

// objectSeverity classifies a confirmed record exposure: the most sensitive
// personal/support standard objects are Critical; every other object (including
// custom __c, whose contents we can't know) is High.
func objectSeverity(name string) severity.Severity {
	if _, ok := criticalObjects[name]; ok {
		return severity.Critical
	}
	return severity.High
}
