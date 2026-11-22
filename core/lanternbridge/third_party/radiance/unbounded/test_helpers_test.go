package unbounded

// countingWidget is a fakeWidget variant whose Stop runs a caller-
// supplied callback before returning. The callback lets the test
// observe shutdown ordering — typically by decrementing a live-
// widget counter so the test can assert that at most one widget is
// alive across a stop/start transition.
type countingWidget struct {
	onStop func()
}

func (w *countingWidget) Stop() {
	if w.onStop != nil {
		w.onStop()
	}
}
