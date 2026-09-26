package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type commitInfo struct {
	hash, date, subject string
}

func gitOutput(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return out.String(), fmt.Errorf("git %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(errb.String()))
	}
	return out.String(), nil
}

// addWorktree checks ref out detached at dir. An existing dir is removed
// from the repository's worktree list first (or deleted outright if git no
// longer knows it), so the checkout is always fresh.
func addWorktree(repo, dir, ref string) error {
	if _, err := os.Stat(dir); err == nil {
		if _, err := gitOutput(repo, "worktree", "remove", "--force", dir); err != nil {
			if rerr := os.RemoveAll(dir); rerr != nil {
				return fmt.Errorf("removing stale worktree: %v; %v", err, rerr)
			}
		}
	}
	// A previous worktree at this path that was deleted by hand leaves a
	// stale registration; prune it before adding.
	if _, err := gitOutput(repo, "worktree", "prune"); err != nil {
		return err
	}
	if _, err := gitOutput(repo, "worktree", "add", "--detach", dir, ref); err != nil {
		return err
	}
	return nil
}

func describeCommit(dir string) (commitInfo, error) {
	out, err := gitOutput(dir, "log", "-1", "--date=iso-strict", "--format=%H%n%ad%n%s")
	if err != nil {
		return commitInfo{}, err
	}
	lines := strings.SplitN(strings.TrimRight(out, "\r\n"), "\n", 3)
	if len(lines) != 3 {
		return commitInfo{}, errors.New("unexpected git log output")
	}
	return commitInfo{hash: strings.TrimSpace(lines[0]), date: strings.TrimSpace(lines[1]), subject: strings.TrimSpace(lines[2])}, nil
}
