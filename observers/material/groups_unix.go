//go:build unix

package main

import "sort"

// sortedGroups returns the ids sorted, for a stable identity.
func sortedGroups(ids []int) []uint32 {
	out := make([]uint32, 0, len(ids))
	for _, id := range ids {
		if id >= 0 {
			out = append(out, uint32(id))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
