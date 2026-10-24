package servicenow_widget_data_exposure

import "github.com/vigolium/vigolium/pkg/types/severity"

// bogusTable is a table name that cannot exist, used as the catch-all negative
// control (a Simple List read of it must not return records).
const bogusTable = "vigolium_nonexistent_probe"

// snTable is a ServiceNow table probed for public-widget exposure. field is the
// display column requested (f=); sev reflects the sensitivity of the leak.
type snTable struct {
	table string
	field string
	label string
	sev   severity.Severity
}

// seedTables (from Aaron Costello's Common_Table_Field_Exposures list) is
// enumerated in full on every confirmed ServiceNow host.
var seedTables = []snTable{
	{"sys_user", "name", "System Users — staff names, emails, phone numbers", severity.Critical},
	{"sys_user_group", "name", "User groups", severity.Medium},
	{"sys_attachment", "file_name", "Attachments — uploaded file names", severity.High},
	{"oauth_entity", "name", "OAuth entities — integration client identifiers/secrets", severity.High},
	{"kb_knowledge", "short_description", "Knowledge base articles", severity.High},
	{"incident", "short_description", "Incidents — support ticket contents", severity.High},
	{"cmdb_ci", "name", "CMDB configuration items — infrastructure inventory", severity.High},
	{"sc_cat_item", "name", "Service catalog items", severity.Medium},
	{"alm_asset", "display_name", "Assets", severity.Medium},
	{"cmn_department", "name", "Departments", severity.Low},
	{"cmdb_model", "name", "CMDB models", severity.Low},
	{"cmn_company", "name", "Companies", severity.Low},
}
