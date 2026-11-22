package main

import (
	"context"

	"github.com/getlantern/radiance/ipc"
)

type UpdateConfigCmd struct{}

func runUpdateConfig(ctx context.Context, c *ipc.Client) error {
	return c.UpdateConfig(ctx)
}
