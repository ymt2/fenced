package main

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
)

func TestSplitDoubleDash(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantPre []string
		wantCmd []string
	}{
		{
			name:    "no double dash treats all args as command",
			args:    []string{"claude", "foo"},
			wantPre: nil,
			wantCmd: []string{"claude", "foo"},
		},
		{
			name:    "double dash at start",
			args:    []string{"--", "claude"},
			wantPre: []string{},
			wantCmd: []string{"claude"},
		},
		{
			name:    "flags before double dash",
			args:    []string{"--fence-log-file", "/tmp/x.log", "--", "claude", "--help"},
			wantPre: []string{"--fence-log-file", "/tmp/x.log"},
			wantCmd: []string{"claude", "--help"},
		},
		{
			name:    "empty after double dash",
			args:    []string{"-m", "--"},
			wantPre: []string{"-m"},
			wantCmd: []string{},
		},
		{
			name:    "empty args",
			args:    nil,
			wantPre: nil,
			wantCmd: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pre, cmd := splitDoubleDash(tt.args)
			if !reflect.DeepEqual(pre, tt.wantPre) {
				t.Errorf("pre = %#v, want %#v", pre, tt.wantPre)
			}
			if !reflect.DeepEqual(cmd, tt.wantCmd) {
				t.Errorf("cmd = %#v, want %#v", cmd, tt.wantCmd)
			}
		})
	}
}

func TestDynamicSocketsIncludesGnuPG(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	gnupg := filepath.Join(home, ".gnupg")
	if err := os.Mkdir(gnupg, 0o700); err != nil {
		t.Fatal(err)
	}
	wantSockets := []string{
		filepath.Join(gnupg, "S.gpg-agent"),
		filepath.Join(gnupg, "S.gpg-agent.ssh"),
		filepath.Join(gnupg, "S.scdaemon"),
		filepath.Join(gnupg, "S.dirmngr"),
		filepath.Join(gnupg, "S.keyboxd"),
	}
	for _, s := range wantSockets {
		if err := os.WriteFile(s, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Decoy: non-matching file in $HOME/.gnupg should not be picked up.
	decoy := filepath.Join(gnupg, "pubring.kbx")
	if err := os.WriteFile(decoy, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	got := dynamicSockets()
	for _, want := range wantSockets {
		if !slices.Contains(got, want) {
			t.Errorf("dynamicSockets() missing %q; got %#v", want, got)
		}
	}
	if slices.Contains(got, decoy) {
		t.Errorf("dynamicSockets() unexpectedly contains decoy %q", decoy)
	}
}
