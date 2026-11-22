package settings

// SetRuntimePaths sets diagnostics paths in memory without loading or writing settings.
func SetRuntimePaths(dataDir, logDir string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	next, err := clone(snapshot())
	if err != nil {
		return err
	}
	if err := next.Set(DataPathKey.String(), dataDir); err != nil {
		return err
	}
	if err := next.Set(LogPathKey.String(), logDir); err != nil {
		return err
	}
	k.k.Store(next)
	return nil
}
