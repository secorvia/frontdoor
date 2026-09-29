//go:build windows

package azcollect

// The Azure CLI ships as a batch shim on Windows, so the bare name does not
// resolve through exec.LookPath the way it does elsewhere.
func azCLIName() string { return "az.cmd" }
