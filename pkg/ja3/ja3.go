package ja3

import (
	"crypto/md5"
	"encoding/hex"
)

func Digest(ja3 string) string {
	h := md5.New()
	h.Write([]byte(ja3))
	return hex.EncodeToString(h.Sum(nil))
}
