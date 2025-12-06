/*
 * Copyright (c) Kapsula, Inc., 2025
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/gin-gonic/gin"
	"github.com/mr-tron/base58"
)

func abs(a int64) int64 {
	if a < 0 {
		return -a
	}
	return a
}

func MakeMessageKey(recipient, sender []byte, timestamp uint64) []byte {
	// m: + sender(32) + recipient(32) + timestamp(8)
	key := make([]byte, 74)
	key[0] = 'm'
	key[1] = ':'
	copy(key[2:34], sender)
	copy(key[34:66], recipient)
	binary.BigEndian.PutUint64(key[66:74], ^timestamp)
	return key
}

func MakeDeviceKey(userPubkey []byte, deviceID string) []byte {
	// d: + userPubkey(32) + deviceID
	key := make([]byte, 2+32+len(deviceID))
	key[0] = 'd'
	key[1] = ':'
	copy(key[2:34], userPubkey)
	copy(key[34:], deviceID)
	return key
}

func MakePendingMessageKey(recipient, sender []byte, timestamp uint64, deviceID string) []byte {
	// p: + deviceID + sender(32) + recipient(32) + timestamp(8)
	deviceIDlen := len(deviceID)
	key := make([]byte, 74+deviceIDlen)
	key[0] = 'p'
	key[1] = ':'
	offset := 2
	copy(key[offset:], deviceID)
	offset += deviceIDlen
	copy(key[offset:], sender)
	offset += 32
	copy(key[offset:], recipient)
	offset += 32
	binary.BigEndian.PutUint64(key[offset:], ^timestamp)
	return key
}

func MakePendingFromMessageKey(messageKey []byte, deviceID string) []byte {
	if len(messageKey) != 74 || messageKey[0] != 'm' {
		return nil
	}
	deviceIDlen := len(deviceID)
	if deviceIDlen == 0 {
		return nil
	}

	key := make([]byte, 2+deviceIDlen+72)
	key[0] = 'p'
	key[1] = ':'
	copy(key[2:], deviceID)
	copy(key[2+deviceIDlen:], messageKey[2:]) // More readable
	return key
}

func MakeMessageKeyFromPending(pendingKey []byte) []byte {
	if len(pendingKey) < 74 || pendingKey[0] != 'p' {
		return nil
	}
	deviceIDlen := len(pendingKey) - 74
	if deviceIDlen <= 0 {
		return nil
	}

	key := make([]byte, 74)
	key[0] = 'm'
	key[1] = ':'
	copy(key[2:], pendingKey[2+deviceIDlen:]) // More readable
	return key
}

func (s *Server) startWriter(db *badger.DB, in <-chan RawMessage, wg *sync.WaitGroup) {
	wg.Add(1)
	defer wg.Done()

	const (
		maxBatch = 10000
		maxWait  = 20 * time.Millisecond
	)

	batch := make([]RawMessage, 0, maxBatch)
	timer := time.NewTimer(maxWait)
	timer.Stop()
	defer timer.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}

		wb := db.NewWriteBatch()
		defer wb.Cancel()

		for _, m := range batch {
			var err error

			if m.Delete {
				// Deletion operation
				err = wb.Delete(m.Key)
			} else {
				// Write operation
				e := badger.NewEntry(m.Key, m.Val)
				if m.TTL > 0 {
					e = e.WithTTL(m.TTL)
				}
				err = wb.SetEntry(e)
			}

			if err != nil {
				log.Printf("WriteBatch operation failed: %v", err)
				return
			}
		}

		if err := wb.Flush(); err != nil {
			log.Printf("WriteBatch flush failed: %v", err)
		}

		batch = batch[:0]
	}

	for {
		select {
		case m, ok := <-in:
			if !ok {
				flush()
				return
			}

			if len(batch) == 0 {
				timer.Reset(maxWait)
			}

			batch = append(batch, m)

			if len(batch) >= maxBatch {
				flush()
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
			}

		case <-timer.C:
			flush()

		case <-s.ctx.Done():
			log.Println("Writer exiting due to context cancellation")
			return
		}
	}
}

func (s *Server) getUserDevices(to []byte) []string {
	if len(to) != 32 {
		return nil
	}

	var devices []string
	_ = s.badger.View(func(txn *badger.Txn) error {
		// immediately create a slice of the required size
		prefix := make([]byte, 2+len(to))
		prefix[0], prefix[1] = 'd', ':'
		copy(prefix[2:], to)

		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			key := it.Item().Key()
			var deviceId = make([]byte, len(key)-34)
			copy(deviceId, key[34:])
			devices = append(devices, string(deviceId))
		}
		return nil
	})
	return devices
}

func (s *Server) sendMessage(c *gin.Context) {
	fromString := strings.TrimSpace(c.GetHeader("X-From"))
	rcptString := strings.TrimSpace(c.GetHeader("X-Rcpt"))
	signatureString := strings.TrimSpace(c.GetHeader("X-Signature"))

	if fromString == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "X-From header is required"})
		return
	}

	if rcptString == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "X-Rcpt header is required"})
		return
	}

	if signatureString == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "X-Signature header is required"})
		return
	}

	// Verify the signatureString
	from, err := base58.Decode(fromString)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Invalid X-From address: %v", err)})
		return
	}
	if len(from) != ed25519.PublicKeySize {
		c.JSON(http.StatusBadRequest, gin.H{"error": "X-From must be a valid ed25519 public messageKey"})
		return
	}
	rcpt, err := base58.Decode(rcptString)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Invalid X-Rcpt address: %v", err)})
		return
	}
	if len(rcpt) != ed25519.PublicKeySize {
		c.JSON(http.StatusBadRequest, gin.H{"error": "X-Rcpt must be a valid ed25519 public messageKey"})
		return
	}

	// Decode the signatureString
	signature, err := base58.Decode(signatureString)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Invalid X-Signature: %v", err)})
		return
	}
	if len(signature) != ed25519.SignatureSize {
		c.JSON(http.StatusBadRequest, gin.H{"error": "X-Signature must be a valid ed25519 signatureString"})
		return
	}

	// Unified timestamp for all operations
	timestamp := uint64(time.Now().UnixNano())

	var data []byte
	if c.Request.ContentLength > 0 {
		data = make([]byte, c.Request.ContentLength)
		_, err = io.ReadFull(io.LimitReader(c.Request.Body, c.Request.ContentLength), data)
	} else {
		data, err = io.ReadAll(c.Request.Body)
	}
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Failed to read request body: %v", err)})
		return
	}

	// Verify signatureString
	isValidSignatureFrom := ed25519.Verify(from, data, signature)
	isValidSignatureRcpt := ed25519.Verify(rcpt, data, signature)

	if !isValidSignatureFrom && !isValidSignatureRcpt {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid signature"})
		return
	}

	// Create a message key with a unified timestamp
	messageKey := MakeMessageKey(rcpt, from, timestamp)

	// Create pending records for all active recipient devices
	var rcptDevices []string
	rcptDevices = s.getUserDevices(rcpt)

	var fromDevices []string
	fromDevices = s.getUserDevices(from)

	// If there are no devices, return an error
	if len(rcptDevices) == 0 && isValidSignatureFrom {
		if os.Getenv("SHOW_NO_DEVICE") != "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "No registered devices"})
		} else {
			c.JSON(http.StatusOK, gin.H{})
		}
		return
	}

	if len(fromDevices) == 0 && isValidSignatureRcpt {
		if os.Getenv("SHOW_NO_DEVICE") != "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "No registered devices"})
		} else {
			c.JSON(http.StatusOK, gin.H{})
		}
		return
	}

	// Send a message
	s.messages <- RawMessage{
		Key: messageKey,
		Val: data,
		TTL: time.Hour * 24 * 7,
	}

	if isValidSignatureFrom {
		for _, device := range rcptDevices {
			pendingKey := MakePendingFromMessageKey(messageKey, device)
			s.messages <- RawMessage{
				Key: pendingKey,
				Val: nil, // empty value for pending records
				TTL: time.Hour * 24 * 7,
			}
		}
	}

	if isValidSignatureRcpt {
		for _, device := range fromDevices {
			pendingKey := MakePendingFromMessageKey(messageKey, device)
			s.messages <- RawMessage{
				Key: pendingKey,
				Val: nil, // empty value for pending records
				TTL: time.Hour * 24 * 7,
			}
		}
	}

	if os.Getenv("SEND_PUSH") != "" && isValidSignatureFrom {
		s.SendPush(base58.Encode(rcpt))
	}
	if os.Getenv("SEND_PUSH") != "" && isValidSignatureRcpt {
		s.SendPush(base58.Encode(from))
	}

	c.JSON(http.StatusOK, gin.H{})
}

func (s *Server) SendPush(to string) {
	body := map[string]interface{}{
		"to":      to,
		"from":    to,
		"message": "\"update\"",
	}
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		log.Printf("Failed to marshal push body: %v", err)
	} else {
		go func() {
			_, err := http.Post("https://presence.kapsula.chat", "application/json", bytes.NewReader(bodyBytes))
			if err != nil {
				log.Printf("Failed to send push notification: %v", err)
			}
		}()
	}
}

func (s *Server) getMessages(c *gin.Context) {
	rcptString := strings.TrimSpace(c.GetHeader("X-Rcpt"))
	if rcptString == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "X-Rcpt header is required"})
		return
	}

	rcpt, err := base58.Decode(rcptString)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Invalid X-Rcpt address: %v", err)})
		return
	}

	if len(rcpt) != ed25519.PublicKeySize {
		c.JSON(http.StatusBadRequest, gin.H{"error": "X-Rcpt must be a valid ed25519 public key"})
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
		c.JSON(http.StatusBadRequest, gin.H{"error": "X-Signature must be a valid ed25519 signature"})
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

	// Check that timestamp is not too old/new (replay protection)
	now := time.Now().Unix()
	if abs(now-timestamp) > 300 { // 5 minutes
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Timestamp too old or in the future"})
		return
	}

	if !ed25519.Verify(rcpt, []byte(timestampString), signature) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid signature"})
		return
	}

	deviceID := strings.TrimSpace(c.GetHeader("X-Device-ID"))
	if deviceID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "X-Device-ID header is required"})
		return
	}

	var messages [][]byte
	err = s.badger.View(func(txn *badger.Txn) error {
		// Prefix for messages: p: + recipient
		prefix := append([]byte("p:"), deviceID...)
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = true
		opts.Prefix = prefix
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			pendingKey := item.KeyCopy(nil)

			// Get message key from pending key
			messageKey := MakeMessageKeyFromPending(pendingKey)
			if messageKey == nil {
				log.Printf("Failed to make message key from pending key: %s", string(item.Key()))
				continue
			}
			// Get message
			data, err := txn.Get(messageKey)
			if err != nil {
				log.Printf("Failed to get message for key %s: %v", string(messageKey), err)
				continue
			}

			// Check key length: m:(2) + sender(32) + recipient(32) + timestamp(8) = 74
			if len(messageKey) != 74 {
				log.Printf("Bad key length: %d %s", len(messageKey))
				continue
			}

			// Recipient already checked via prefix, additional check not needed

			// Read message value
			err = data.Value(func(val []byte) error {
				msgCopy := make([]byte, len(messageKey)-2+len(val))
				copy(msgCopy, messageKey[2:])
				copy(msgCopy[len(messageKey)-2:], val)
				messages = append(messages, msgCopy)
				return nil
			})
			if err != nil {
				return err
			}

			// Send command to delete pending record
			s.messages <- RawMessage{
				Key:    pendingKey,
				Delete: true,
			}
		}
		return nil
	})

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to get messages: %v", err)})
		return
	}

	c.JSON(http.StatusOK, messages)
}
