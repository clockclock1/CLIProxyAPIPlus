// Package executor provides runtime execution capabilities for various AI service providers.
// This file implements device fingerprinting for Codex to match official OpenAI clients.
package executor

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/google/uuid"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

var (
	// codexDeviceIDCache stores the persistent device ID
	codexDeviceIDCache   string
	codexDeviceIDCacheMu sync.RWMutex
	codexDeviceIDOnce    sync.Once
)

// getCodexDeviceID returns a stable device ID for OpenAI requests.
// This mimics the behavior of official OpenAI clients that maintain a persistent device identifier.
// The device ID is stored in a platform-specific location and persists across sessions.
func getCodexDeviceID() string {
	codexDeviceIDOnce.Do(func() {
		// Try to load from persistent storage first
		if id := loadCodexDeviceIDFromDisk(); id != "" {
			codexDeviceIDCache = id
			return
		}
		
		// Generate a new stable device ID based on machine characteristics
		codexDeviceIDCache = generateStableCodexDeviceID()
		
		// Try to persist it for future use
		saveCodexDeviceIDToDisk(codexDeviceIDCache)
	})
	
	codexDeviceIDCacheMu.RLock()
	defer codexDeviceIDCacheMu.RUnlock()
	return codexDeviceIDCache
}

// loadCodexDeviceIDFromDisk attempts to load a persisted device ID from disk.
// Storage location matches OpenAI client conventions:
// - macOS: ~/Library/Application Support/openai/device_id
// - Windows: %APPDATA%/openai/device_id
// - Linux: ~/.local/share/openai/device_id
func loadCodexDeviceIDFromDisk() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	
	var deviceIDPath string
	switch runtime.GOOS {
	case "darwin":
		deviceIDPath = filepath.Join(homeDir, "Library", "Application Support", "openai", "device_id")
	case "windows":
		appData := os.Getenv("APPDATA")
		if appData == "" {
			appData = filepath.Join(homeDir, "AppData", "Roaming")
		}
		deviceIDPath = filepath.Join(appData, "openai", "device_id")
	default: // linux and other unix-like
		deviceIDPath = filepath.Join(homeDir, ".local", "share", "openai", "device_id")
	}
	
	data, err := os.ReadFile(deviceIDPath)
	if err != nil {
		return ""
	}
	
	deviceID := strings.TrimSpace(string(data))
	if deviceID != "" {
		log.Debugf("codex: loaded device ID from %s", deviceIDPath)
	}
	return deviceID
}

// saveCodexDeviceIDToDisk attempts to persist the device ID to disk for future sessions.
func saveCodexDeviceIDToDisk(deviceID string) {
	if deviceID == "" {
		return
	}
	
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return
	}
	
	var deviceIDPath string
	switch runtime.GOOS {
	case "darwin":
		deviceIDPath = filepath.Join(homeDir, "Library", "Application Support", "openai", "device_id")
	case "windows":
		appData := os.Getenv("APPDATA")
		if appData == "" {
			appData = filepath.Join(homeDir, "AppData", "Roaming")
		}
		deviceIDPath = filepath.Join(appData, "openai", "device_id")
	default: // linux and other unix-like
		deviceIDPath = filepath.Join(homeDir, ".local", "share", "openai", "device_id")
	}
	
	// Create directory if it doesn't exist
	dir := filepath.Dir(deviceIDPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Debugf("codex: failed to create device ID directory: %v", err)
		return
	}
	
	// Write device ID to file
	if err := os.WriteFile(deviceIDPath, []byte(deviceID), 0644); err != nil {
		log.Debugf("codex: failed to save device ID: %v", err)
		return
	}
	
	log.Debugf("codex: saved device ID to %s", deviceIDPath)
}

// generateStableCodexDeviceID generates a stable device ID based on machine characteristics.
// This creates a deterministic ID that remains consistent across sessions on the same machine.
func generateStableCodexDeviceID() string {
	// Collect machine-specific information
	hostname, _ := os.Hostname()
	homeDir, _ := os.UserHomeDir()
	
	// Create a stable hash from machine characteristics
	h := sha256.New()
	h.Write([]byte(hostname))
	h.Write([]byte(homeDir))
	h.Write([]byte(runtime.GOOS))
	h.Write([]byte(runtime.GOARCH))
	
	// Generate a UUID-like string from the hash
	hash := hex.EncodeToString(h.Sum(nil))
	
	// Format as UUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
	if len(hash) >= 32 {
		return hash[0:8] + "-" + hash[8:12] + "-" + hash[12:16] + "-" + hash[16:20] + "-" + hash[20:32]
	}
	
	// Fallback to random UUID if hash is somehow invalid
	return uuid.NewString()
}

// resolveCodexDeviceID attempts to get device ID from auth metadata,
// falling back to a generated stable ID.
func resolveCodexDeviceID(auth *cliproxyauth.Auth) string {
	if auth != nil && auth.Metadata != nil {
		if deviceID, ok := auth.Metadata["device_id"].(string); ok {
			if trimmed := strings.TrimSpace(deviceID); trimmed != "" {
				return trimmed
			}
		}
	}
	return getCodexDeviceID()
}
