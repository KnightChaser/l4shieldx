// xdpcollector/utility/path.go
package utility

import (
	"os"
	"path/filepath"
)

// GetProjectRoot returns the root directory of the project where the executable is located.
func GetProjectRoot() string {
	exe, _ := os.Executable()
	return filepath.Dir(exe)
}
