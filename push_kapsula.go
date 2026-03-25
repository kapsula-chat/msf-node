/*
 * Copyright (c) Kapsula, Inc., 2025
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/mr-tron/base58"
)

type pushMessageWebhookRequest struct {
	EventID             string   `json:"eventId"`
	RecipientPublicKeys []string `json:"recipientPublicKeys"`
	SenderPublicKey     string   `json:"senderPublicKey"`
	Preview             string   `json:"preview"`
	ChatID              string   `json:"chatId"`
	Timestamp           int64    `json:"timestamp"`
	Lang                string   `json:"lang,omitempty"`
}

const msfKeySecretPath = "/run/secrets/MSF_KEY"

func normalizePushURL() string {
	base := strings.TrimSpace(os.Getenv("KAPSULA_PUSH_URL"))
	if base == "" {
		base = "https://push.kapsula.chat"
	}
	return strings.TrimSuffix(base, "/")
}

func buildMessageChatID(a, b string) string {
	pair := []string{a, b}
	sort.Strings(pair)
	return pair[0] + ":" + pair[1]
}

func (s *Server) SendPush(recipientPublicKey, senderPublicKey string) {
	recipientPublicKey = strings.TrimSpace(recipientPublicKey)
	senderPublicKey = strings.TrimSpace(senderPublicKey)

	if recipientPublicKey == "" || senderPublicKey == "" {
		return
	}

	nodePublicKey := resolveNodePublicKey()
	accessToken := strings.TrimSpace(os.Getenv("KAPSULA_PUSH_ACCESS_TOKEN"))

	if accessToken == "" && nodePublicKey == "" {
		return
	}

	go s.sendPushWebhook(recipientPublicKey, senderPublicKey)
}

func (s *Server) sendPushWebhook(recipientPublicKey, senderPublicKey string) {
	nodePublicKey := resolveNodePublicKey()
	accessToken := strings.TrimSpace(os.Getenv("KAPSULA_PUSH_ACCESS_TOKEN"))

	payload := pushMessageWebhookRequest{
		EventID:             "msg-" + uuid.NewString(),
		RecipientPublicKeys: []string{recipientPublicKey},
		SenderPublicKey:     senderPublicKey,
		Preview:             "",
		ChatID:              buildMessageChatID(recipientPublicKey, senderPublicKey),
		Timestamp:           time.Now().UnixMilli(),
	}
	if lang := strings.TrimSpace(os.Getenv("KAPSULA_PUSH_LANG")); lang != "" {
		payload.Lang = lang
	}

	body, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Failed to marshal push webhook payload: %v", err)
		return
	}

	endpoint := normalizePushURL() + "/webhook/message"
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		log.Printf("Failed to create push webhook request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	// Access token issued for this service.
	if accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}
	// Optional compatibility header for allowlist mode on push service.
	if nodePublicKey != "" {
		req.Header.Set("X-Node-Public-Key", nodePublicKey)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("Failed to call kapsula-push webhook: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusMultiStatus {
		log.Printf("kapsula-push webhook failed: status=%s recipient=%s sender=%s", resp.Status, recipientPublicKey, senderPublicKey)
		return
	}

	log.Printf("kapsula-push webhook sent: status=%d recipient=%s", resp.StatusCode, recipientPublicKey)
}

func resolveNodePublicKey() string {
	// Derive the node public key from the mounted secret to avoid duplicated config.
	privSerialized := readMSFKeySecret()
	if privSerialized == "" {
		return ""
	}

	raw, err := parseSerializedByteArray(privSerialized)
	if err != nil {
		return ""
	}

	switch len(raw) {
	case ed25519.SeedSize:
		return base58.Encode(ed25519.NewKeyFromSeed(raw).Public().(ed25519.PublicKey))
	case ed25519.PrivateKeySize:
		return base58.Encode(ed25519.PrivateKey(raw).Public().(ed25519.PublicKey))
	}

	return ""
}

func readMSFKeySecret() string {
	file, err := os.Open(msfKeySecretPath)
	if err != nil {
		return ""
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(data))
}

func parseSerializedByteArray(value string) ([]byte, error) {
	var ints []int
	if err := json.Unmarshal([]byte(value), &ints); err != nil {
		return nil, err
	}

	raw := make([]byte, len(ints))
	for i, n := range ints {
		if n < 0 || n > 255 {
			return nil, fmt.Errorf("byte value out of range at index %d", i)
		}
		raw[i] = byte(n)
	}

	return raw, nil
}

func (s *Server) SendPushLegacy(recipientPublicKey string) {
	body := map[string]any{
		"to":      recipientPublicKey,
		"from":    recipientPublicKey,
		"message": "{\"type\":\"message\"}",
	}
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		log.Printf("Failed to marshal legacy push body: %v", err)
		return
	}
	response, err := http.Post("https://presence.kapsula.chat/push", "application/json", bytes.NewReader(bodyBytes))
	if err != nil {
		log.Printf("Failed to send legacy push notification: %v", err)
		return
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		log.Printf("Legacy push notification failed with status: %s", response.Status)
	}
}

func validateKapsulaPushConfig() error {
	accessToken := strings.TrimSpace(os.Getenv("KAPSULA_PUSH_ACCESS_TOKEN"))
	if accessToken == "" {
		return fmt.Errorf("KAPSULA_PUSH_ACCESS_TOKEN is not set; push webhook calls will likely be unauthorized")
	}
	if readMSFKeySecret() == "" {
		return fmt.Errorf("MSF push key is not available at %s; X-Node-Public-Key will be omitted", msfKeySecretPath)
	}
	return nil
}
