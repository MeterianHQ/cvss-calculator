package main

import (
	"testing"
)

// almostEqual compares two float64 values within a small margin of error.
func almostEqual(a, b float64) bool {
	diff := a - b
	if diff < 0 {
		diff = -diff
	}
	const epsilon = 0.1
	return diff < epsilon
}

func TestCVSS2(t *testing.T) {
	vector := "AV:N/AC:L/Au:N/C:P/I:P/A:P"
	expected := CvssResult{
		Version: "2.0",
		Vector:  vector,
		Score:   7.5,
	}
	result := handleCVSS2(vector)

	if result.Version != expected.Version {
		t.Errorf("CVSS2: Expected version %s, got %s", expected.Version, result.Version)
	}
	if result.Vector != expected.Vector {
		t.Errorf("CVSS2: Expected vector %s, got %s", expected.Vector, result.Vector)
	}
	if !almostEqual(result.Score, expected.Score) {
		t.Errorf("CVSS2: Expected score %f, got %f", expected.Score, result.Score)
	}
}

func TestCVSS30(t *testing.T) {
	vector := "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
	expected := CvssResult{
		Version: "3.0",
		Vector:  vector,
		Score:   6.1,
	}
	result := handleCVSS30(vector)

	if result.Version != expected.Version {
		t.Errorf("CVSS3.0: Expected version %s, got %s", expected.Version, result.Version)
	}
	if result.Vector != expected.Vector {
		t.Errorf("CVSS3.0: Expected vector %s, got %s", expected.Vector, result.Vector)
	}
	if !almostEqual(result.Score, expected.Score) {
		t.Errorf("CVSS3.0: Expected score %f, got %f", expected.Score, result.Score)
	}
}

func TestCVSS31(t *testing.T) {
	vector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N"
	expected := CvssResult{
		Version: "3.1",
		Vector:  vector,
		Score:   7.5,
	}
	result := handleCVSS31(vector)

	if result.Version != expected.Version {
		t.Errorf("CVSS3.1: Expected version %s, got %s", expected.Version, result.Version)
	}
	if result.Vector != expected.Vector {
		t.Errorf("CVSS3.1: Expected vector %s, got %s", expected.Vector, result.Vector)
	}
	if !almostEqual(result.Score, expected.Score) {
		t.Errorf("CVSS3.1: Expected score %f, got %f", expected.Score, result.Score)
	}
}

func TestCVSS40(t *testing.T) {
	vector := "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
	expected := CvssResult{
		Version: "4.0",
		Vector:  vector,
		Score:   9.3,
	}
	result := handleCVSS4(vector)

	if result.Version != expected.Version {
		t.Errorf("CVSS4.0: Expected version %s, got %s", expected.Version, result.Version)
	}
	if result.Vector != expected.Vector {
		t.Errorf("CVSS4.0: Expected vector %s, got %s", expected.Vector, result.Vector)
	}
	if !almostEqual(result.Score, expected.Score) {
		t.Errorf("CVSS4.0: Expected score %f, got %f", expected.Score, result.Score)
	}
}
