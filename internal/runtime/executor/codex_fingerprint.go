// Package executor provides runtime execution capabilities for various AI service providers.
// This file implements deep fingerprinting for Codex with per-account randomization.
package executor

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"time"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

// codexFingerprint represents a complete browser/client fingerprint
type codexFingerprint struct {
	// User-Agent components
	UserAgent            string
	Originator           string
	
	// Stainless SDK version info
	PackageVersion       string
	RuntimeVersion       string
	OS                   string
	Arch                 string
	
	// Browser-like headers
	AcceptLanguage       string
	SecChUa              string
	SecChUaMobile        string
	SecChUaPlatform      string
	
	// Additional entropy
	Timezone             string
	ScreenResolution     string
	ColorDepth           int
	HardwareConcurrency  int
}

var (
	// fingerprintCache stores per-account fingerprints
	fingerprintCache   = make(map[string]*codexFingerprint)
	fingerprintCacheMu sync.RWMutex
)

// Realistic version pools based on actual OpenAI SDK releases
var (
	// OpenAI Node SDK versions (recent releases)
	nodeSDKVersions = []string{
		"4.73.1", "4.73.0", "4.72.0", "4.71.1", "4.71.0",
		"4.70.1", "4.70.0", "4.69.0", "4.68.1", "4.68.0",
		"4.67.3", "4.67.2", "4.67.1", "4.67.0", "4.66.1",
	}
	
	// Node.js runtime versions (LTS and current)
	nodeRuntimeVersions = []string{
		"v22.11.0", "v22.10.0", "v22.9.0", "v22.8.0",
		"v20.18.0", "v20.17.0", "v20.16.0", "v20.15.1",
		"v18.20.4", "v18.20.3", "v18.20.2", "v18.20.1",
	}
	
	// Operating systems with realistic distribution
	operatingSystems = []osInfo{
		{name: "MacOS", weight: 35},
		{name: "Windows", weight: 45},
		{name: "Linux", weight: 20},
	}
	
	// CPU architectures
	architectures = []archInfo{
		{name: "arm64", os: "MacOS", weight: 70},
		{name: "x64", os: "MacOS", weight: 30},
		{name: "x64", os: "Windows", weight: 95},
		{name: "arm64", os: "Windows", weight: 5},
		{name: "x64", os: "Linux", weight: 90},
		{name: "arm64", os: "Linux", weight: 10},
	}
	
	// Accept-Language variations (realistic distribution)
	acceptLanguages = []langInfo{
		{value: "en-US,en;q=0.9", weight: 40},
		{value: "en-GB,en;q=0.9", weight: 10},
		{value: "zh-CN,zh;q=0.9,en;q=0.8", weight: 15},
		{value: "ja-JP,ja;q=0.9,en;q=0.8", weight: 8},
		{value: "de-DE,de;q=0.9,en;q=0.8", weight: 7},
		{value: "fr-FR,fr;q=0.9,en;q=0.8", weight: 6},
		{value: "es-ES,es;q=0.9,en;q=0.8", weight: 5},
		{value: "ko-KR,ko;q=0.9,en;q=0.8", weight: 4},
		{value: "ru-RU,ru;q=0.9,en;q=0.8", weight: 3},
		{value: "pt-BR,pt;q=0.9,en;q=0.8", weight: 2},
	}
	
	// Timezones (major cities)
	timezones = []string{
		"America/New_York", "America/Los_Angeles", "America/Chicago",
		"Europe/London", "Europe/Paris", "Europe/Berlin",
		"Asia/Shanghai", "Asia/Tokyo", "Asia/Seoul",
		"Australia/Sydney", "America/Toronto", "Asia/Singapore",
	}
	
	// Screen resolutions (common desktop/laptop)
	screenResolutions = []string{
		"1920x1080", "2560x1440", "3840x2160", // Desktop
		"1366x768", "1440x900", "1536x864",    // Laptop
		"2880x1800", "3024x1964", "3456x2234", // MacBook Pro
	}
	
	// Hardware concurrency (CPU cores)
	hardwareConcurrencies = []int{4, 6, 8, 10, 12, 16}
)

type osInfo struct {
	name   string
	weight int
}

type archInfo struct {
	name   string
	os     string
	weight int
}

type langInfo struct {
	value  string
	weight int
}

// getOrCreateFingerprint returns a cached fingerprint or creates a new one for the account
func getOrCreateFingerprint(auth *cliproxyauth.Auth) *codexFingerprint {
	accountKey := getAccountFingerprintKey(auth)
	
	fingerprintCacheMu.RLock()
	if fp, exists := fingerprintCache[accountKey]; exists {
		fingerprintCacheMu.RUnlock()
		return fp
	}
	fingerprintCacheMu.RUnlock()
	
	// Create new fingerprint
	fingerprintCacheMu.Lock()
	defer fingerprintCacheMu.Unlock()
	
	// Double-check after acquiring write lock
	if fp, exists := fingerprintCache[accountKey]; exists {
		return fp
	}
	
	fp := generateFingerprint(accountKey)
	fingerprintCache[accountKey] = fp
	return fp
}

// getAccountFingerprintKey generates a stable key for fingerprint caching
func getAccountFingerprintKey(auth *cliproxyauth.Auth) string {
	if auth == nil {
		return "default"
	}
	
	// Priority: account_id > email > client_id > auth.ID
	if auth.Metadata != nil {
		if accountID, ok := auth.Metadata["account_id"].(string); ok && accountID != "" {
			return "account:" + accountID
		}
		if email, ok := auth.Metadata["email"].(string); ok && email != "" {
			return "email:" + email
		}
		if clientID, ok := auth.Metadata["client_id"].(string); ok && clientID != "" {
			return "client:" + clientID
		}
	}
	
	if auth.ID != "" {
		return "id:" + auth.ID
	}
	
	return "default"
}

// generateFingerprint creates a realistic, randomized fingerprint based on account key
func generateFingerprint(accountKey string) *codexFingerprint {
	// Use account key as seed for deterministic randomization
	seed := hashToSeed(accountKey)
	rng := rand.New(rand.NewSource(seed))
	
	// Select OS with weighted distribution
	os := selectWeightedOS(rng)
	
	// Select architecture based on OS
	arch := selectWeightedArch(rng, os)
	
	// Select SDK and runtime versions
	sdkVersion := nodeSDKVersions[rng.Intn(len(nodeSDKVersions))]
	runtimeVersion := nodeRuntimeVersions[rng.Intn(len(nodeRuntimeVersions))]
	
	// Select language with weighted distribution
	language := selectWeightedLanguage(rng)
	
	// Generate User-Agent
	userAgent := fmt.Sprintf("OpenAI/JS %s", sdkVersion)
	
	// Generate Sec-CH-UA headers (Chrome-like)
	secChUa := generateSecChUa(rng, sdkVersion)
	secChUaPlatform := fmt.Sprintf("\"%s\"", os)
	
	// Select other random attributes
	timezone := timezones[rng.Intn(len(timezones))]
	resolution := screenResolutions[rng.Intn(len(screenResolutions))]
	colorDepth := []int{24, 30, 32}[rng.Intn(3)]
	hwConcurrency := hardwareConcurrencies[rng.Intn(len(hardwareConcurrencies))]
	
	return &codexFingerprint{
		UserAgent:           userAgent,
		Originator:          "openai-node",
		PackageVersion:      sdkVersion,
		RuntimeVersion:      runtimeVersion,
		OS:                  os,
		Arch:                arch,
		AcceptLanguage:      language,
		SecChUa:             secChUa,
		SecChUaMobile:       "?0",
		SecChUaPlatform:     secChUaPlatform,
		Timezone:            timezone,
		ScreenResolution:    resolution,
		ColorDepth:          colorDepth,
		HardwareConcurrency: hwConcurrency,
	}
}

// hashToSeed converts a string to a deterministic seed
func hashToSeed(s string) int64 {
	h := sha256.Sum256([]byte(s))
	// Use first 8 bytes as seed
	seed := int64(0)
	for i := 0; i < 8; i++ {
		seed = (seed << 8) | int64(h[i])
	}
	return seed
}

// selectWeightedOS selects an OS based on weighted distribution
func selectWeightedOS(rng *rand.Rand) string {
	totalWeight := 0
	for _, os := range operatingSystems {
		totalWeight += os.weight
	}
	
	r := rng.Intn(totalWeight)
	cumulative := 0
	for _, os := range operatingSystems {
		cumulative += os.weight
		if r < cumulative {
			return os.name
		}
	}
	
	return operatingSystems[0].name
}

// selectWeightedArch selects an architecture based on OS and weighted distribution
func selectWeightedArch(rng *rand.Rand, os string) string {
	// Filter architectures for the selected OS
	var candidates []archInfo
	totalWeight := 0
	for _, arch := range architectures {
		if arch.os == os {
			candidates = append(candidates, arch)
			totalWeight += arch.weight
		}
	}
	
	if len(candidates) == 0 {
		return "x64" // fallback
	}
	
	r := rng.Intn(totalWeight)
	cumulative := 0
	for _, arch := range candidates {
		cumulative += arch.weight
		if r < cumulative {
			return arch.name
		}
	}
	
	return candidates[0].name
}

// selectWeightedLanguage selects a language based on weighted distribution
func selectWeightedLanguage(rng *rand.Rand) string {
	totalWeight := 0
	for _, lang := range acceptLanguages {
		totalWeight += lang.weight
	}
	
	r := rng.Intn(totalWeight)
	cumulative := 0
	for _, lang := range acceptLanguages {
		cumulative += lang.weight
		if r < cumulative {
			return lang.value
		}
	}
	
	return acceptLanguages[0].value
}

// generateSecChUa generates a realistic Sec-CH-UA header
func generateSecChUa(rng *rand.Rand, sdkVersion string) string {
	// Chrome versions that might be used with Node.js
	chromeVersions := []int{120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130}
	chromeVersion := chromeVersions[rng.Intn(len(chromeVersions))]
	
	// Generate realistic Sec-CH-UA
	return fmt.Sprintf("\"Chromium\";v=\"%d\", \"Not(A:Brand\";v=\"24\", \"Google Chrome\";v=\"%d\"",
		chromeVersion, chromeVersion)
}

// applyFingerprintToHeaders applies the fingerprint to HTTP headers
func applyFingerprintToHeaders(headers map[string]string, fp *codexFingerprint) {
	if fp == nil {
		return
	}
	
	// Core SDK headers
	headers["User-Agent"] = fp.UserAgent
	headers["X-Stainless-Package-Version"] = fp.PackageVersion
	headers["X-Stainless-Runtime-Version"] = fp.RuntimeVersion
	headers["X-Stainless-Os"] = fp.OS
	headers["X-Stainless-Arch"] = fp.Arch
	
	// Language
	headers["Accept-Language"] = fp.AcceptLanguage
	
	// Browser-like headers (optional, for enhanced realism)
	// These are typically not sent by Node.js but can be added for extra entropy
	// Uncomment if you want to simulate browser-like behavior:
	// headers["Sec-CH-UA"] = fp.SecChUa
	// headers["Sec-CH-UA-Mobile"] = fp.SecChUaMobile
	// headers["Sec-CH-UA-Platform"] = fp.SecChUaPlatform
}

// getFingerprintSummary returns a human-readable summary of the fingerprint
func getFingerprintSummary(fp *codexFingerprint) string {
	if fp == nil {
		return "no fingerprint"
	}
	return fmt.Sprintf("SDK:%s Node:%s OS:%s/%s Lang:%s",
		fp.PackageVersion, fp.RuntimeVersion, fp.OS, fp.Arch,
		strings.Split(fp.AcceptLanguage, ",")[0])
}

// generateDynamicFingerprint creates a completely random fingerprint (not cached)
// Use this for testing or when you want maximum randomness
func generateDynamicFingerprint() *codexFingerprint {
	seed := time.Now().UnixNano()
	rng := rand.New(rand.NewSource(seed))
	
	os := selectWeightedOS(rng)
	arch := selectWeightedArch(rng, os)
	sdkVersion := nodeSDKVersions[rng.Intn(len(nodeSDKVersions))]
	runtimeVersion := nodeRuntimeVersions[rng.Intn(len(nodeRuntimeVersions))]
	language := selectWeightedLanguage(rng)
	
	return &codexFingerprint{
		UserAgent:           fmt.Sprintf("OpenAI/JS %s", sdkVersion),
		Originator:          "openai-node",
		PackageVersion:      sdkVersion,
		RuntimeVersion:      runtimeVersion,
		OS:                  os,
		Arch:                arch,
		AcceptLanguage:      language,
		SecChUa:             generateSecChUa(rng, sdkVersion),
		SecChUaMobile:       "?0",
		SecChUaPlatform:     fmt.Sprintf("\"%s\"", os),
		Timezone:            timezones[rng.Intn(len(timezones))],
		ScreenResolution:    screenResolutions[rng.Intn(len(screenResolutions))],
		ColorDepth:          []int{24, 30, 32}[rng.Intn(3)],
		HardwareConcurrency: hardwareConcurrencies[rng.Intn(len(hardwareConcurrencies))],
	}
}

// GetOrCreateFingerprint returns a cached fingerprint or creates a new one for the account (exported for testing)
func GetOrCreateFingerprint(auth *cliproxyauth.Auth) *codexFingerprint {
	return getOrCreateFingerprint(auth)
}

// GetFingerprintSummary returns a human-readable summary of the fingerprint (exported for testing)
func GetFingerprintSummary(fp *codexFingerprint) string {
	return getFingerprintSummary(fp)
}

// ExportFingerprintStats returns statistics about cached fingerprints (exported for testing)
func ExportFingerprintStats() map[string]interface{} {
	return exportFingerprintStats()
}

// ClearFingerprintCache clears the fingerprint cache (exported for testing)
func ClearFingerprintCache() {
	clearFingerprintCache()
}

// clearFingerprintCache clears the fingerprint cache (useful for testing)
func clearFingerprintCache() {
	fingerprintCacheMu.Lock()
	defer fingerprintCacheMu.Unlock()
	fingerprintCache = make(map[string]*codexFingerprint)
}

// exportFingerprintStats returns statistics about cached fingerprints
func exportFingerprintStats() map[string]interface{} {
	fingerprintCacheMu.RLock()
	defer fingerprintCacheMu.RUnlock()
	
	stats := map[string]interface{}{
		"total_cached": len(fingerprintCache),
		"os_distribution": make(map[string]int),
		"arch_distribution": make(map[string]int),
		"sdk_versions": make(map[string]int),
	}
	
	osDist := stats["os_distribution"].(map[string]int)
	archDist := stats["arch_distribution"].(map[string]int)
	sdkVers := stats["sdk_versions"].(map[string]int)
	
	for _, fp := range fingerprintCache {
		osDist[fp.OS]++
		archDist[fp.Arch]++
		sdkVers[fp.PackageVersion]++
	}
	
	return stats
}

// generateFingerprintHash generates a unique hash for a fingerprint
func generateFingerprintHash(fp *codexFingerprint) string {
	if fp == nil {
		return ""
	}
	
	data := fmt.Sprintf("%s|%s|%s|%s|%s|%s",
		fp.UserAgent, fp.PackageVersion, fp.RuntimeVersion,
		fp.OS, fp.Arch, fp.AcceptLanguage)
	
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:8]) // First 8 bytes
}
