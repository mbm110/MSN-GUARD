package helper

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	usagePairingA = "11111111-1111-4111-8111-111111111111"
	usagePairingB = "22222222-2222-4222-8222-222222222222"
)

func TestUsageAddsUpTakesAndRestores(t *testing.T) {
	var u Usage
	u.Add(usagePairingB, 30)
	u.Add(usagePairingA, 50)
	u.Add(usagePairingA, 20)
	u.Add(usagePairingA, 0)
	u.Add("", 99)
	got := u.Take()
	assert.Equal(t, []PairedBytes{{PairingID: usagePairingA, Bytes: 70}, {PairingID: usagePairingB, Bytes: 30}}, got)
	assert.Nil(t, u.Take(), "a take clears what it returned")

	u.Add(usagePairingA, 5)
	u.Restore(got)
	assert.Equal(t, []PairedBytes{{PairingID: usagePairingA, Bytes: 75}, {PairingID: usagePairingB, Bytes: 30}}, u.Take())
}

func TestUsageTakeFlushesFirst(t *testing.T) {
	var u Usage
	u.SetFlush(func() { u.Add(usagePairingA, 8) })
	assert.Equal(t, []PairedBytes{{PairingID: usagePairingA, Bytes: 8}}, u.Take())
}

func TestNilUsageIsInert(t *testing.T) {
	var u *Usage
	u.Add(usagePairingA, 1)
	u.SetFlush(func() {})
	u.Restore([]PairedBytes{{PairingID: usagePairingA, Bytes: 1}})
	assert.Nil(t, u.Take())
}
