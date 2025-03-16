package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	gocvss20 "github.com/pandatix/go-cvss/20"
	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
	gocvss40 "github.com/pandatix/go-cvss/40"
)

const version = "1.0"

type CvssResult struct {
	Version string  `json:"version"`
	Vector  string  `json:"vector"`
	Score   float64 `json:"score"`
}

func main() {
	// If no argument or a help/version flag is provided, handle them.
	if len(os.Args) < 2 {
		printHelp()
		return
	}

	// Check for --help or --version flag
	firstArg := os.Args[1]
	if firstArg == "--help" {
		printHelp()
		return
	}
	if firstArg == "--version" {
		fmt.Printf("CVSS Calculator version %s\n", version)
		return
	}

	// Process each provided vector
	for _, vector := range os.Args[1:] {
		// Skip any help or version argument if accidentally included later
		if vector == "--help" || vector == "--version" {
			continue
		}

		var result CvssResult

		switch {
		case strings.HasPrefix(vector, "CVSS:4.0"):
			result = handleCVSS4(vector)
		case strings.HasPrefix(vector, "CVSS:3.1"):
			result = handleCVSS31(vector)
		case strings.HasPrefix(vector, "CVSS:3.0"):
			result = handleCVSS30(vector)
		case strings.HasPrefix(vector, "AV:"):
			result = handleCVSS2(vector)
		default:
			// Skip unsupported vectors
			continue
		}

		jsonResult, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			log.Fatalf("Error marshaling JSON: %v", err)
		}

		fmt.Println(string(jsonResult))
	}
}

func printHelp() {
	progName := os.Args[0]
	helpText := fmt.Sprintf(`CVSS Calculator version %s
 - produces a JSON representation of one or more CVSS vectors
 - supports CVSS2.0, CVSS3.0, CVSS3.1, CVSS4.0

Usage:
  %s [--help|--version] <CVSS_vector1> [<CVSS_vector2> ...]

Supported vector formats:
  CVSS:4.0/...
  CVSS:3.1/...
  CVSS:3.0/...
  AV:... (for CVSS v2)

Example:
  %s "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
`, version, progName, progName)
	fmt.Print(helpText)
}

func handleCVSS4(vector string) CvssResult {
	cvss, err := gocvss40.ParseVector(vector)
	if err != nil {
		log.Fatalf("Error parsing CVSS v4 vector: %v", err)
	}

	score := cvss.Score()

	return CvssResult{
		Version: "4.0",
		Vector:  vector,
		Score:   score,
	}
}

func handleCVSS31(vector string) CvssResult {
	cvss, err := gocvss31.ParseVector(vector)
	if err != nil {
		log.Fatalf("Error parsing CVSS v3.1 vector: %v", err)
	}

	score := cvss.BaseScore()
	return CvssResult{
		Version: "3.1",
		Vector:  vector,
		Score:   score,
	}
}

func handleCVSS30(vector string) CvssResult {
	cvss, err := gocvss30.ParseVector(vector)
	if err != nil {
		log.Fatalf("Error parsing CVSS v3.0 vector: %v", err)
	}

	score := cvss.BaseScore()
	return CvssResult{
		Version: "3.0",
		Vector:  vector,
		Score:   score,
	}
}

func handleCVSS2(vector string) CvssResult {
	c, err := gocvss20.ParseVector(vector)
	if err != nil {
		log.Fatalf("Error parsing CVSS v2 vector: %v", err)
	}

	score := c.BaseScore()
	return CvssResult{
		Version: "2.0",
		Vector:  vector,
		Score:   score,
	}
}
