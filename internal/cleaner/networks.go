package cleaner

import (
	"context"
	"log/slog"

	"github.com/docker/docker/api/types/network"
	dockerclient "github.com/docker/docker/client"
)

// builtinNetworks are Docker-managed networks that must never be removed.
var builtinNetworks = map[string]bool{
	"bridge": true,
	"host":   true,
	"none":   true,
}

// RemoveUnusedNetworks removes custom networks that have no containers connected.
func RemoveUnusedNetworks(ctx context.Context, cli *dockerclient.Client, dryRun bool) (int, error) {
	networks, err := cli.NetworkList(ctx, network.ListOptions{})
	if err != nil {
		return 0, err
	}

	removed := 0
	for _, n := range networks {
		if builtinNetworks[n.Name] {
			continue
		}
		if len(n.Containers) > 0 {
			continue
		}

		prefix := ""
		if dryRun {
			prefix = "[DRY-RUN] "
		}
		slog.Info(prefix+"would remove unused network",
			"component", "cleaner",
			"action", "remove_network",
			"resource_id", n.ID,
			"name", n.Name,
			"driver", n.Driver,
		)

		if dryRun {
			removed++
			continue
		}

		if err := cli.NetworkRemove(ctx, n.ID); err != nil {
			slog.Warn("failed to remove network", "id", n.ID, "name", n.Name, "error", err)
			continue
		}
		removed++
		slog.Info("removed unused network", "component", "cleaner", "action", "remove_network", "resource_id", n.ID, "name", n.Name)
	}

	return removed, nil
}
