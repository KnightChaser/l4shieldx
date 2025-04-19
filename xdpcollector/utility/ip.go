// xdpcollector/utility/ip.go
package utility

import (
	"encoding/binary"
	"fmt"
)

func IntToIPv4(i uint32) string {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, i)
	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
}
