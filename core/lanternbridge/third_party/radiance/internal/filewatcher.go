package internal

import (
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"log/slog"

	"github.com/fsnotify/fsnotify"
)

// FileWatcher watches a file for changes and calls a callback function when the file is modified.
type FileWatcher struct {
	watcher  *fsnotify.Watcher
	path     string
	callback func()
	closeC   chan struct{}
	started  atomic.Bool
}

// NewFileWatcher creates a new file watcher for the given path and callback function.
func NewFileWatcher(path string, callback func()) *FileWatcher {
	path, _ = filepath.Abs(path)
	return &FileWatcher{
		path:     path,
		callback: callback,
	}
}

func (fw *FileWatcher) Start() error {
	if !fw.started.CompareAndSwap(false, true) {
		slog.Debug("File watcher already started")
		return nil
	}
	slog.Debug("Starting file watcher for " + fw.path)
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		fw.started.Store(false)
		return fmt.Errorf("start watcher: %w", err)
	}
	fw.watcher = watcher
	go fw.watchLoop()

	err = watcher.Add(filepath.Dir(fw.path))
	if err != nil {
		fw.started.Store(false)
		return fmt.Errorf("failed to add watcher: %w", err)
	}
	fw.closeC = make(chan struct{})
	return nil
}

func (fw *FileWatcher) Close() error {
	if !fw.started.CompareAndSwap(true, false) {
		return nil
	}
	close(fw.closeC)
	return fw.watcher.Close()
}

func (fw *FileWatcher) watchLoop() {
	var (
		// time to wait for no new events before calling the callback
		waitFor = 100 * time.Millisecond

		timer       *time.Timer
		timerAccess sync.Mutex
	)
	for {
		select {
		case event, ok := <-fw.watcher.Events:
			if !ok {
				return
			}
			if event.Name != fw.path || (!event.Has(fsnotify.Create) && !event.Has(fsnotify.Write)) {
				continue
			}

			// since files can be written in chunks, we need to wait until the whole file is written.
			// we create a timer that will call the callback after not receiving any more events for
			// a bit. If we receive another event while waiting, we reset the timer.
			timerAccess.Lock()
			if timer == nil {
				timer = time.AfterFunc(waitFor, func() {
					fw.callback()
					timerAccess.Lock()
					timer = nil
					timerAccess.Unlock()
				})
			} else {
				timer.Reset(waitFor)
			}
			timerAccess.Unlock()
		case err, ok := <-fw.watcher.Errors:
			if !ok {
				return
			}
			slog.Error("Error watching file:", "error", err)
		case <-fw.closeC:
			return
		}
	}
}
