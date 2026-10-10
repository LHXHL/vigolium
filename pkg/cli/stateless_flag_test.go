package cli

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// shorthandOwners maps every command path in the tree to the name of the flag
// that binds -S on it ("" when none), the observable result of
// addStatelessShorthand.
func shorthandOwners(root *cobra.Command) map[string]string {
	out := map[string]string{}
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		name := ""
		if f := c.Flags().ShorthandLookup("S"); f != nil {
			name = f.Name
		}
		out[c.CommandPath()] = name
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(root)
	return out
}

// mergeAll forces cobra's lazy persistent-flag merge on every command, the
// state a tree is left in after help rendering or an executed test.
func mergeAll(c *cobra.Command) {
	_ = c.InheritedFlags()
	_ = c.LocalFlags()
	for _, sub := range c.Commands() {
		mergeAll(sub)
	}
}

// statelessFixtureTree mirrors the shapes addStatelessShorthand has to handle:
// the root's long-only persistent --stateless, a command with its own
// -S/--stateless, a command holding the retired -S tombstone, and plain
// commands (one nested) that get the injected -S.
func statelessFixtureTree() *cobra.Command {
	noop := func(*cobra.Command, []string) {}
	root := &cobra.Command{Use: "vigolium", Run: noop}
	registerStatelessRootFlag(root)

	own := &cobra.Command{Use: "finding", Run: noop}
	own.Flags().BoolVarP(&globalStateless, "stateless", "S", false, "")

	tomb := &cobra.Command{Use: "server", Run: noop}
	registerScanOnReceiveFlags(tomb.Flags(), "")

	plain := &cobra.Command{Use: "log", Run: noop}
	plainChild := &cobra.Command{Use: "ls", Run: noop}
	plain.AddCommand(plainChild)

	root.AddCommand(own, tomb, plain)
	return root
}

// The injected -S must not depend on whether cobra merged the root's persistent
// --stateless into a command's flagset before the walk. It used to: a merged
// command already "had" a flag named stateless, so it was skipped, and whether
// root carried -S varied with test order.
func TestAddStatelessShorthandIgnoresMergeOrder(t *testing.T) {
	fresh := statelessFixtureTree()
	addStatelessShorthand(fresh)

	merged := statelessFixtureTree()
	mergeAll(merged)
	addStatelessShorthand(merged)

	want := map[string]string{
		"vigolium":         statelessShorthandFlag,
		"vigolium finding": "stateless",
		"vigolium server":  retiredScanOnReceiveFlag,
		"vigolium log":     statelessShorthandFlag,
		"vigolium log ls":  statelessShorthandFlag,
	}
	assert.Equal(t, want, shorthandOwners(fresh))
	assert.Equal(t, want, shorthandOwners(merged))

	// A second walk (prepareCommandTree runs once per test that needs it) is a
	// no-op, and merging afterwards does not panic or change the answer.
	addStatelessShorthand(fresh)
	mergeAll(fresh)
	assert.Equal(t, want, shorthandOwners(fresh))

	// -S before the subcommand resolves the path on root: it is a bool there,
	// so "finding" is not swallowed as its value.
	for _, root := range []*cobra.Command{fresh, merged} {
		cmd, _, err := root.Find([]string{"-S", "finding"})
		require.NoError(t, err)
		assert.Equal(t, "finding", cmd.Name())
	}
}

// The real tree gives the same answer however often prepareCommandTree runs and
// whatever cobra merged in between.
func TestPrepareCommandTreeStatelessDeterministic(t *testing.T) {
	prepareCommandTree(rootCmd)
	before := shorthandOwners(rootCmd)
	mergeAll(rootCmd)
	prepareCommandTree(rootCmd)
	assert.Equal(t, before, shorthandOwners(rootCmd))

	assert.Equal(t, statelessShorthandFlag, before["vigolium"], "root must accept -S so `vigolium -S finding` resolves")
	assert.Equal(t, retiredScanOnReceiveFlag, before["vigolium server"])
	assert.Equal(t, "stateless", before["vigolium finding"])
	for path, name := range before {
		assert.NotEmpty(t, name, "%s: -S must parse on every command", path)
	}
}
