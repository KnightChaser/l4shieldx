// xdpcollector/utility/path.go
package utility

import (
	"os"
	"path/filepath"
)

// GetProjectRoot returns the root directory of the project where the executable is located.
func GetProjectRoot() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Dir(exe), nil
}
