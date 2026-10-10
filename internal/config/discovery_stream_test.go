package config

import (
	"testing"
	"time"
)

func TestDiscoveryFlushIntervalValue(t *testing.T) {
	cases := map[string]time.Duration{
		"":    0, // source default
		"30s": 30 * time.Second,
		"0":   -1, // off
		"0s":  -1,
	}
	for in, want := range cases {
		c := &DiscoveryConfig{FlushInterval: in}
		if got := c.FlushIntervalValue(); got != want {
			t.Errorf("FlushIntervalValue(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestDiscoveryValidateStreamingAndConcurrency(t *testing.T) {
	valid := []func(*DiscoveryConfig){
		func(c *DiscoveryConfig) {},
		func(c *DiscoveryConfig) { c.FlushInterval = "0" },
		func(c *DiscoveryConfig) { c.FlushInterval = "5s"; c.TargetConcurrency = 1 },
		func(c *DiscoveryConfig) { c.TargetConcurrency = maxDiscoveryTargetConcurrency },
	}
	for i, mutate := range valid {
		c := DefaultDiscoveryConfig()
		mutate(c)
		if err := c.Validate(); err != nil {
			t.Errorf("valid case %d: %v", i, err)
		}
	}
	invalid := []func(*DiscoveryConfig){
		func(c *DiscoveryConfig) { c.FlushInterval = "soon" },
		func(c *DiscoveryConfig) { c.FlushInterval = "100ms" },
		func(c *DiscoveryConfig) { c.TargetConcurrency = -1 },
		func(c *DiscoveryConfig) { c.TargetConcurrency = maxDiscoveryTargetConcurrency + 1 },
	}
	for i, mutate := range invalid {
		c := DefaultDiscoveryConfig()
		mutate(c)
		if err := c.Validate(); err == nil {
			t.Errorf("invalid case %d validated", i)
		}
	}
}

func TestDiscoveryStreamsFuzz(t *testing.T) {
	if !DefaultDiscoveryConfig().StreamsFuzz() {
		t.Error("stream_fuzz must default to true")
	}
	on, off := true, false
	if !(&DiscoveryConfig{StreamFuzz: &on}).StreamsFuzz() {
		t.Error("stream_fuzz: true")
	}
	if (&DiscoveryConfig{StreamFuzz: &off}).StreamsFuzz() {
		t.Error("stream_fuzz: false must keep the fuzz class to the end of the target")
	}
}
