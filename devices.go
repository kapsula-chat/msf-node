/*
 * Copyright (c) Kapsula, Inc., 2025
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package main

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/mr-tron/base58/base58"
)

func (s *Server) registerDevice(c *gin.Context) {
	fromString := c.GetHeader("X-From")
	if fromString == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "X-From header is required"})
		return
	}
	from, err := base58.Decode(fromString)
	if err != nil || len(from) != 32 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid X-From header"})
		return
	}
	deviceId := c.GetHeader("X-Device-ID")
	if deviceId == "" {
		deviceId = uuid.NewString()
	}

	deviceKey := MakeDeviceKey(from, deviceId)
	deviceInfo := DeviceInfo{
		PushId:       c.GetHeader("X-Push-ID"),
		RegisteredAt: time.Now(),
	}
	deviceInfoBytes, err := json.Marshal(deviceInfo)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to marshal device info"})
		return
	}
	s.messages <- RawMessage{
		Key: deviceKey,
		Val: deviceInfoBytes,
	}
	c.JSON(http.StatusOK, gin.H{"device_id": deviceId})
}

func (s *Server) unregisterDevice(c *gin.Context) {
	from := c.GetHeader("X-From")
	if from == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "X-From header is required"})
		return
	}
	fromDecoded, err := base58.Decode(from)
	if err != nil || len(fromDecoded) != 32 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid X-From header"})
		return
	}
	deviceIdStr := c.GetHeader("X-Device-ID")
	if deviceIdStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "X-Device-ID header is required"})
		return
	}

	key := MakeDeviceKey(fromDecoded, deviceIdStr)
	s.messages <- RawMessage{
		Key:    key,
		Val:    nil,
		Delete: true,
	}
	c.JSON(http.StatusOK, gin.H{})
}

func (s *Server) listDevices(c *gin.Context) {
	fromString := c.GetHeader("X-From")
	if fromString == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "X-From header is required"})
		return
	}
	from, err := base58.Decode(fromString)
	if err != nil || len(from) != 32 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid X-From header"})
		return
	}

	signatureString := strings.TrimSpace(c.GetHeader("X-Signature"))
	if signatureString == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "X-Signature header is required"})
		return
	}

	// Decode signatureString
	signature, err := base58.Decode(signatureString)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Invalid X-Signature: %v", err)})
		return
	}
	if len(signature) != ed25519.SignatureSize {
		c.JSON(http.StatusBadRequest, gin.H{"error": "X-Signature must be a valid ed25519 signatureString"})
		return
	}

	timestampString := strings.TrimSpace(c.GetHeader("X-Timestamp"))
	if timestampString == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "X-Timestamp header is required"})
		return
	}

	timestamp, err := strconv.ParseInt(timestampString, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Invalid X-Timestamp: %v", err)})
		return
	}

	// Check the timestamp is within 5 minutes to prevent replay attacks
	now := time.Now().UnixNano()
	if abs(now-timestamp) > 300 { // 5-minute tolerance
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Timestamp too old or in the future"})
		return
	}

	if !ed25519.Verify(from, []byte(timestampString), signature) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid signature"})
		return
	}

	devices := s.getUserDevices(from)
	c.JSON(http.StatusOK, gin.H{"devices": devices})
}
