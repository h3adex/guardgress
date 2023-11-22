package annotations

import (
	"github.com/h3adex/guardgress/pkg/mocks"
	"github.com/h3adex/guardgress/pkg/models"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestAnnotations(t *testing.T) {
	ingresses := mocks.IngressMock()
	assert.Equal(t, IsTlsFingerprintBlacklisted(ingresses.Items[0].Annotations, models.ClientHelloParsed{Ja3: "d41d8cd98f00b204e9800998ecf8427a"}), true)
	assert.Equal(t, AddJa3Header(ingresses.Items[0].Annotations), true)
}
