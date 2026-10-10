package action

// ActiveConsumers returns how many claimed states have not been released.
func (u *UnfiredFragmentCandidates) ActiveConsumers() int {
	return int(u.active.Load())
}
