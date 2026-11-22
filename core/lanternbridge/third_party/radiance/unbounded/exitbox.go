package unbounded

import (
	"context"
	"fmt"

	"github.com/getlantern/lantern-box/node"
	sbox "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/experimental/libbox"
	sblog "github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"

	"github.com/getlantern/radiance/internal/hostaccess"
)

// newExitBox builds and starts a direct exit box, as lantern-box's own does: sing-box in a
// clone of ctx's service registry, so it keeps ctx's registries but registers its managers
// only in its own, with a log factory that logs nothing, since the box carries strangers'
// destinations. It also refuses options that grant host access, as radiance does for every
// peer box. ctx must come from exitContext.
func newExitBox(ctx context.Context, options string) (node.ExitBox, error) {
	ctx = newExitBoxContext(ctx)
	opts, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(options))
	if err != nil {
		return nil, fmt.Errorf("decode exit box options: %w", err)
	}
	if err := hostaccess.CheckOptions(opts); err != nil {
		return nil, fmt.Errorf("check exit box options: %w", err)
	}
	b, err := sbox.New(sbox.Options{Context: ctx, Options: opts})
	if err != nil {
		return nil, fmt.Errorf("build exit box: %w", err)
	}
	if err := b.Start(); err != nil {
		_ = b.Close()
		return nil, fmt.Errorf("start exit box: %w", err)
	}
	return exitBox{b: b, ctx: ctx}, nil
}

// newExitBoxContext is an exit box's clone of ctx's service registry. With exitContext's platform
// interface, it registers a wrapper of the platform for the box alone: sing-box initializes the
// wrapper with the box's network manager, and the exit runs a box per kind, and two across a
// rotation.
func newExitBoxContext(ctx context.Context) context.Context {
	ctx = service.ExtendContext(ctx)
	service.MustRegister[sblog.Factory](ctx, sblog.NewNOPFactory())
	if platform, _ := ctx.Value(exitPlatformKey{}).(libbox.PlatformInterface); platform != nil {
		service.MustRegister[adapter.PlatformInterface](ctx, libbox.NewPlatformInterfaceWrapper(platform))
	}
	return ctx
}

type exitBox struct {
	b   *sbox.Box
	ctx context.Context
}

func (x exitBox) Router() adapter.ConnectionRouterEx { return x.b.Router() }
func (x exitBox) ResetNetwork()                      { x.b.Network().ResetNetwork(x.ctx) }
func (x exitBox) Close() error                       { return x.b.Close() }
