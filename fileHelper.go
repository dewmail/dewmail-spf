package main

import (
	"bufio"
	"fmt"
	"os"
)

/**
 * Loads keys from file
 */
func LoadKeys(sFile string) error {
	// Open file
	fpFile, err := os.Open(sFile)
	if err != nil {
		return fmt.Errorf("Failed to open file %s", sFile)
	}
	Scanner := bufio.NewScanner(fpFile)
	Scanner.Split(bufio.ScanLines)
	defer fpFile.Close()

	// Count by lines
	for i := 0; Scanner.Scan(); i++ {
		validAPIKeys[Scanner.Text()] = true
	}
	return nil
}
