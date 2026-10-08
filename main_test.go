package main

import "testing"

func TestCLIExitStatus(t *testing.T) {
	for _, tt := range []struct {
		name string
		args []string
		want int
	}{
		{"help", []string{"--help"}, 0},
		{"login help", []string{"login", "--help"}, 0},
		{"scan help", []string{"scan", "--help"}, 0},
		{"missing command", nil, 1},
		{"unknown command", []string{"unknown"}, 1},
		{"missing voucher", []string{"login"}, 1},
		{"unknown option", []string{"scan", "--unknown"}, 1},
		{"invalid scan MAC", []string{"scan", "extra"}, 1},
		{"non-hex scan MAC", []string{"scan", "02000000000z"}, 1},
		{"short scan MAC", []string{"scan", "02000000000"}, 1},
		{"long scan MAC", []string{"scan", "0200000000000"}, 1},
		{"invalid subsequent scan MAC", []string{"scan", "020000000001", "invalid"}, 1},
		{"unexpected login argument", []string{"login", "TEST-VOUCHER", "extra"}, 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			captureStdout(t, func() {
				if got := runCLI(tt.args); got != tt.want {
					t.Errorf("exit status: got %d, want %d", got, tt.want)
				}
			})
		})
	}
}
