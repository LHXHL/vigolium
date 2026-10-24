package salesforce_aura_apex_execution

// apexProbe is a single ApexActionController.execute target: a namespace, class
// and no-argument method.
type apexProbe struct {
	namespace string
	classname string
	method    string
}

// benignProbe is the read-only, side-effect-free managed-package method used to
// confirm guest Apex reachability. Wave.Templates.getTemplates is the documented
// probe (sf_apex_execution): it takes no arguments, only reads CRM Analytics
// templates, and returns a SUCCESS envelope when — and only when — the Guest can
// invoke @AuraEnabled Apex. When the org lacks the Wave namespace or blocks the
// guest, it returns a non-success state and the module cleanly does not fire.
var benignProbe = apexProbe{namespace: "Wave", classname: "Templates", method: "getTemplates"}

// bogusProbePre and bogusProbePost are namespace/class/method triples that cannot
// resolve to any real Apex. They are the catch-all negative control: an endpoint
// that returns SUCCESS for these would return SUCCESS for anything, so any
// positive would be a false positive and the host is skipped. Two distinct triples
// are checked — one before and one after the benign rounds — so a transient fluke
// can't pass both.
var (
	bogusProbePre  = apexProbe{namespace: "Vigolium", classname: "NoSuchController", method: "vigoliumNoSuchMethod"}
	bogusProbePost = apexProbe{namespace: "Vigolium2", classname: "AbsentApexClass", method: "vigoliumAbsentMethod"}
)
