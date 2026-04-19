// Package update handles the compose-file-based update action.
//
// The update flow:
//  1. Handler issues a server-generated token and prompts user to re-type the service name.
//  2. User submits the form; the server validates token + service name.
//  3. If valid, runs `docker compose -f <path> pull && docker compose -f <path> up -d <service>`.
//  4. Output is captured and stored in the actions table for the audit log.
//
// All exec.Command calls use arg slices — no shell interpolation.
package update

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// TokenLength is the number of random bytes in a confirmation token.
const TokenLength = 16

// GenerateToken creates a cryptographically random confirmation token.
func GenerateToken() (string, error) {
	b := make([]byte, TokenLength)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// Runner executes compose update commands.
type Runner struct {
	// DockerBinary is the path to the docker binary. Defaults to "docker".
	DockerBinary string
}

// DefaultRunner returns a Runner using the system docker binary.
func DefaultRunner() *Runner {
	return &Runner{DockerBinary: "docker"}
}

// Result holds the output of an update run.
type Result struct {
	Output     string
	Err        error
	FinishedAt time.Time
}

// Run executes `docker compose -f <composePath> pull <service>` followed by
// `docker compose -f <composePath> up -d <service>`.
//
// Both commands use arg slices — no shell interpolation.
func (r *Runner) Run(ctx context.Context, composePath, service string) *Result {
	binary := r.DockerBinary
	if binary == "" {
		binary = "docker"
	}

	var out strings.Builder

	// Step 1: pull.
	pullArgs := []string{"compose", "-f", composePath, "pull", service}
	pullOut, pullErr := runCmd(ctx, binary, pullArgs)
	out.WriteString("=== docker compose pull ===\n")
	out.WriteString(pullOut)
	if pullErr != nil {
		out.WriteString(fmt.Sprintf("\nERROR: %v\n", pullErr))
		return &Result{Output: out.String(), Err: pullErr, FinishedAt: time.Now()}
	}

	// Step 2: up -d.
	upArgs := []string{"compose", "-f", composePath, "up", "-d", service}
	upOut, upErr := runCmd(ctx, binary, upArgs)
	out.WriteString("\n=== docker compose up -d ===\n")
	out.WriteString(upOut)
	if upErr != nil {
		out.WriteString(fmt.Sprintf("\nERROR: %v\n", upErr))
		return &Result{Output: out.String(), Err: upErr, FinishedAt: time.Now()}
	}

	return &Result{Output: out.String(), FinishedAt: time.Now()}
}

func runCmd(ctx context.Context, binary string, args []string) (string, error) {
	cmd := exec.CommandContext(ctx, binary, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	combined := stdout.String()
	if stderr.Len() > 0 {
		combined += "\nSTDERR:\n" + stderr.String()
	}
	return combined, err
}
