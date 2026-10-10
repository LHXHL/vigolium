package infra

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLinkHostHeaderVariants(t *testing.T) {
	t.Parallel()
	var names []string
	for _, v := range LinkHostHeaderVariants() {
		names = append(names, v.Header)
		assert.True(t, v.CarriesHost(), v.Header)
	}
	assert.Equal(t, []string{"Host", "X-Forwarded-Host", "X-Host", "Forwarded"}, names)
}

func TestHostHeaderVariantValue(t *testing.T) {
	t.Parallel()
	byName := map[string]HostHeaderVariant{}
	for _, v := range HostHeaderVariants {
		byName[v.Header] = v
	}
	assert.Equal(t, "host=cb.example", byName["Forwarded"].Value("cb.example"))
	assert.Equal(t, "cb.example", byName["X-Forwarded-Host"].Value("cb.example"))
	assert.Equal(t, "nothttps", byName["X-Forwarded-Proto"].Value("cb.example"), "literal variants ignore the host")
	assert.False(t, byName["X-Forwarded-Port"].CarriesHost())
}
