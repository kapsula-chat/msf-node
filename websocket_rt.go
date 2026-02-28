/*
 * Copyright (c) Kapsula, Inc., 2025
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package main

import (
	"crypto/ed25519"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"github.com/mr-tron/base58"
)

type wsSubscriber struct {
	conn     net.Conn
	rcpt     string
	deviceID string
	mu       sync.Mutex
}

func (s *wsSubscriber) writeBinary(payload []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return wsutil.WriteServerMessage(s.conn, ws.OpBinary, payload)
}

type wsHub struct {
	mu      sync.RWMutex
	clients map[string]map[*wsSubscriber]struct{}
}

func newWSHub() *wsHub {
	return &wsHub{
		clients: make(map[string]map[*wsSubscriber]struct{}),
	}
}

func wsKey(rcpt, deviceID string) string {
	return rcpt + "|" + deviceID
}

func (h *wsHub) add(sub *wsSubscriber) {
	key := wsKey(sub.rcpt, sub.deviceID)
	h.mu.Lock()
	defer h.mu.Unlock()
	set := h.clients[key]
	if set == nil {
		set = make(map[*wsSubscriber]struct{})
		h.clients[key] = set
	}
	set[sub] = struct{}{}
}

func (h *wsHub) remove(sub *wsSubscriber) {
	key := wsKey(sub.rcpt, sub.deviceID)
	h.mu.Lock()
	defer h.mu.Unlock()
	set := h.clients[key]
	if set == nil {
		return
	}
	delete(set, sub)
	if len(set) == 0 {
		delete(h.clients, key)
	}
}

func (h *wsHub) list(rcpt, deviceID string) []*wsSubscriber {
	key := wsKey(rcpt, deviceID)
	h.mu.RLock()
	defer h.mu.RUnlock()
	set := h.clients[key]
	if len(set) == 0 {
		return nil
	}
	out := make([]*wsSubscriber, 0, len(set))
	for sub := range set {
		out = append(out, sub)
	}
	return out
}

var globalWSHub = newWSHub()

func formatWSMessagePayload(messageKey, body []byte) []byte {
	// ws payload format expected by bots: sender(32) + recipient(32) + timestamp(8) + ciphertext
	if len(messageKey) != 74 {
		return nil
	}
	out := make([]byte, 72+len(body))
	copy(out, messageKey[2:])
	copy(out[72:], body)
	return out
}

func (s *Server) publishToDeviceWS(recipient []byte, deviceID string, payload []byte) {
	if len(recipient) != ed25519.PublicKeySize || deviceID == "" || len(payload) == 0 {
		return
	}
	rcpt := base58.Encode(recipient)
	subs := globalWSHub.list(rcpt, deviceID)
	for _, sub := range subs {
		if err := sub.writeBinary(payload); err != nil {
			log.Printf("ws write failed for %s/%s: %v", rcpt, deviceID, err)
			globalWSHub.remove(sub)
			_ = sub.conn.Close()
		}
	}
}

func (s *Server) websocketMessages(c *gin.Context) {
	rcptString := strings.TrimSpace(c.GetHeader("X-Rcpt"))
	if rcptString == "" {
		c.JSON(400, gin.H{"error": "X-Rcpt header is required"})
		return
	}
	rcpt, err := base58.Decode(rcptString)
	if err != nil || len(rcpt) != ed25519.PublicKeySize {
		c.JSON(400, gin.H{"error": "Invalid X-Rcpt address"})
		return
	}

	signatureString := strings.TrimSpace(c.GetHeader("X-Signature"))
	if signatureString == "" {
		c.JSON(400, gin.H{"error": "X-Signature header is required"})
		return
	}
	signature, err := base58.Decode(signatureString)
	if err != nil || len(signature) != ed25519.SignatureSize {
		c.JSON(400, gin.H{"error": "Invalid X-Signature"})
		return
	}

	timestampString := strings.TrimSpace(c.GetHeader("X-Timestamp"))
	if timestampString == "" {
		c.JSON(400, gin.H{"error": "X-Timestamp header is required"})
		return
	}
	timestamp, err := strconv.ParseInt(timestampString, 10, 64)
	if err != nil {
		c.JSON(400, gin.H{"error": fmt.Sprintf("Invalid X-Timestamp: %v", err)})
		return
	}
	if abs(time.Now().Unix()-timestamp) > 300 {
		c.JSON(401, gin.H{"error": "Timestamp too old or in the future"})
		return
	}
	if !ed25519.Verify(rcpt, []byte(timestampString), signature) {
		c.JSON(401, gin.H{"error": "Invalid signature"})
		return
	}

	deviceID := strings.TrimSpace(c.GetHeader("X-Device-ID"))
	if deviceID == "" {
		c.JSON(400, gin.H{"error": "X-Device-ID header is required"})
		return
	}

	isRegistered := false
	for _, d := range s.getUserDevices(rcpt) {
		if d == deviceID {
			isRegistered = true
			break
		}
	}
	if !isRegistered {
		c.JSON(401, gin.H{"error": "Device is not registered for recipient"})
		return
	}

	conn, _, _, err := ws.UpgradeHTTP(c.Request, c.Writer)
	if err != nil {
		return
	}

	sub := &wsSubscriber{
		conn:     conn,
		rcpt:     rcptString,
		deviceID: deviceID,
	}
	globalWSHub.add(sub)
	defer func() {
		globalWSHub.remove(sub)
		_ = conn.Close()
	}()

	// Keep connection alive and handle control frames until client disconnects.
	reader := wsutil.NewReader(conn, ws.StateServerSide)
	reader.OnIntermediate = wsutil.ControlFrameHandler(conn, ws.StateServerSide)
	for {
		h, err := reader.NextFrame()
		if err != nil {
			return
		}
		if h.OpCode == ws.OpClose {
			return
		}
		if h.Length > 0 {
			if _, err := io.CopyN(io.Discard, reader, int64(h.Length)); err != nil {
				return
			}
		}
	}
}
