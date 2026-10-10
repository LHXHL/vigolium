package terminal

import "testing"

func TestColorDecision(t *testing.T) {
	none := colorEnv{}
	cases := []struct {
		name           string
		mode           ColorMode
		stdout, stderr bool
		env            colorEnv
		want           bool
	}{
		{"auto both tty", ColorAuto, true, true, none, true},
		{"auto stdout piped", ColorAuto, false, true, none, false},
		{"auto stderr piped", ColorAuto, true, false, none, false},
		{"auto neither tty", ColorAuto, false, false, none, false},
		{"auto NO_COLOR", ColorAuto, true, true, colorEnv{NoColor: "1"}, false},
		{"auto FORCE_COLOR piped", ColorAuto, false, false, colorEnv{ForceColor: "1"}, true},
		{"auto FORCE_COLOR=0 on tty", ColorAuto, true, true, colorEnv{ForceColor: "0"}, false},
		{"auto FORCE_COLOR=false on tty", ColorAuto, true, true, colorEnv{ForceColor: "false"}, false},
		{"auto CLICOLOR_FORCE piped", ColorAuto, false, false, colorEnv{CLIColorForce: "1"}, true},
		{"auto CLICOLOR_FORCE=0 piped", ColorAuto, false, false, colorEnv{CLIColorForce: "0"}, false},
		{"auto NO_COLOR beats FORCE_COLOR", ColorAuto, false, false, colorEnv{NoColor: "1", ForceColor: "1"}, false},
		{"always piped", ColorAlways, false, false, none, true},
		{"always beats NO_COLOR", ColorAlways, false, false, colorEnv{NoColor: "1"}, true},
		{"never on tty", ColorNever, true, true, none, false},
		{"never beats FORCE_COLOR", ColorNever, true, true, colorEnv{ForceColor: "1"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := colorDecision(tc.mode, tc.stdout, tc.stderr, tc.env); got != tc.want {
				t.Errorf("colorDecision(%s, stdout=%v, stderr=%v, %+v) = %v, want %v",
					tc.mode, tc.stdout, tc.stderr, tc.env, got, tc.want)
			}
		})
	}
}

func TestParseColorMode(t *testing.T) {
	for in, want := range map[string]ColorMode{"": ColorAuto, "auto": ColorAuto, "ALWAYS": ColorAlways, " never ": ColorNever} {
		got, err := ParseColorMode(in)
		if err != nil || got != want {
			t.Errorf("ParseColorMode(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := ParseColorMode("sometimes"); err == nil {
		t.Error("ParseColorMode(sometimes) = nil error, want a rejection")
	}
}

func TestApplyColorModeMachineForcesNever(t *testing.T) {
	restore := IsColorEnabled()
	t.Cleanup(func() { SetColorEnabled(restore) })
	ApplyColorMode(ColorAlways, true)
	if IsColorEnabled() {
		t.Error("machine output must force color off even under --color=always")
	}
	ApplyColorMode(ColorAlways, false)
	if !IsColorEnabled() {
		t.Error("--color=always must enable color when no machine mode is active")
	}
}
