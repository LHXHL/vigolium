package node2shell

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCarriesJSONBody(t *testing.T) {
	t.Parallel()

	assert.True(t, CarriesJSONBody("POST", "application/json; charset=utf-8"))
	assert.True(t, CarriesJSONBody("PATCH", "application/vnd.api+json"))
	assert.False(t, CarriesJSONBody("PUT", "application/json"), "PUT {} can replace a resource")
	assert.False(t, CarriesJSONBody("GET", "application/json"))
	assert.False(t, CarriesJSONBody("POST", "application/x-www-form-urlencoded"))
	assert.False(t, CarriesJSONBody("POST", ""))
}
