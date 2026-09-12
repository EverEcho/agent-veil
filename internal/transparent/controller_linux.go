//go:build linux

package transparent

import (
	"context"
	"sync"
	"time"

	"github.com/agentveil/agentveil/internal/domain"
)

// LinuxCAController coordinates private CA material with the Linux system
// trust adapter. Reconcile makes interrupted rotations converge to one trusted
// active CA or to no CA after deactivation.
type LinuxCAController struct {
	material *CAStore
	trust    *LinuxTrustStore
	mu       sync.Mutex
}

func NewLinuxCAController(material *CAStore, trust *LinuxTrustStore) (*LinuxCAController, error) {
	if material == nil || trust == nil {
		return nil, domain.NewError(domain.ErrInvalidContract, "create Linux CA controller", "material and trust stores are required")
	}
	return &LinuxCAController{material: material, trust: trust}, nil
}

func (c *LinuxCAController) Rotate(ctx context.Context, now time.Time) (CA, error) {
	if c == nil || ctx == nil || now.IsZero() {
		return CA{}, domain.NewError(domain.ErrInvalidContract, "rotate Linux CA", "controller, context, and rotation time are required")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.reconcileLocked(ctx); err != nil {
		return CA{}, err
	}
	previous, hadPrevious, err := c.material.Active()
	if err != nil {
		return CA{}, err
	}
	candidate, err := CreateCA(c.material.root, now)
	if err != nil {
		return CA{}, err
	}
	receipt, err := c.trust.Install(ctx, candidate)
	if err != nil {
		return CA{}, err
	}
	if err := c.material.Activate(candidate); err != nil {
		uninstallErr := c.trust.Uninstall(ctx, receipt)
		removeErr := candidate.Remove()
		if uninstallErr != nil || removeErr != nil {
			return CA{}, domain.NewError(domain.ErrInvalidContract, "rotate Linux CA", "activation failed and candidate rollback was incomplete")
		}
		return CA{}, err
	}
	if hadPrevious {
		if err := c.retire(ctx, previous); err != nil {
			return candidate, domain.NewError(domain.ErrInvalidContract, "rotate Linux CA", "new CA is active but previous CA retirement is incomplete")
		}
	}
	return candidate, nil
}

func (c *LinuxCAController) Reconcile(ctx context.Context) error {
	if c == nil || ctx == nil {
		return domain.NewError(domain.ErrInvalidContract, "reconcile Linux CAs", "controller and context are required")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reconcileLocked(ctx)
}

func (c *LinuxCAController) Revoke(ctx context.Context) (bool, error) {
	if c == nil || ctx == nil {
		return false, domain.NewError(domain.ErrInvalidContract, "revoke Linux CA", "controller and context are required")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	active, ok, err := c.material.DeactivateActive()
	if err != nil || !ok {
		return false, err
	}
	if err := c.retire(ctx, active); err != nil {
		return false, domain.NewError(domain.ErrInvalidContract, "revoke Linux CA", "CA is inactive but trust retirement is incomplete")
	}
	return true, nil
}

func (c *LinuxCAController) reconcileLocked(ctx context.Context) error {
	active, hasActive, err := c.material.Active()
	if err != nil {
		return err
	}
	if hasActive {
		if _, err := c.trust.Install(ctx, active); err != nil {
			return domain.NewError(domain.ErrInvalidContract, "reconcile Linux CAs", "active CA trust could not be refreshed")
		}
	}
	all, err := LoadCAs(c.material.root)
	if err != nil {
		return err
	}
	for _, candidate := range all {
		if hasActive && candidate.directory == active.directory {
			continue
		}
		if err := c.retire(ctx, candidate); err != nil {
			return domain.NewError(domain.ErrInvalidContract, "reconcile Linux CAs", "inactive CA retirement is incomplete")
		}
	}
	return nil
}

func (c *LinuxCAController) retire(ctx context.Context, ca CA) error {
	receipt, err := c.trust.Receipt(ca)
	if err != nil {
		return err
	}
	if err := c.trust.Uninstall(ctx, receipt); err != nil {
		return err
	}
	if err := ca.Remove(); err != nil {
		return err
	}
	return nil
}
