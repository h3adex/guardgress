package ja3

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestJa3Digest(t *testing.T) {
	ja3 := Digest("")
	assert.Equal(t, "d41d8cd98f00b204e9800998ecf8427e", ja3)
}
