/*
 * Copyright (c) Kapsula, Inc., 2025
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package main

import (
	"context"
	"os"
	"sync"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/gin-gonic/gin"
)

type RawMessage struct {
	Key    []byte
	Val    []byte
	TTL    time.Duration
	Delete bool
}

type Server struct {
	router   *gin.Engine        // Gin router for handling HTTP requests
	dataDir  string             // Directory for storing chat files and requests
	shutdown chan os.Signal     // Channel for graceful shutdown
	ctx      context.Context    // Context for cancellation
	cancel   context.CancelFunc // Function to cancel context
	wg       sync.WaitGroup     // WaitGroup for goroutines
	badger   *badger.DB
	messages chan RawMessage

	// Cached badger metrics (updated periodically by background collector)
	badgerMu           sync.RWMutex
	badgerTotalSize    uint64    // total size of Badger files in bytes
	badgerSSTFiles     int       // number of .sst files
	badgerVlogFiles    int       // number of .vlog files
	badgerLastObserved time.Time // last time metrics were collected
}

type DeviceInfo struct {
	PushId       string    `json:"push_id"`       // Push notification identifier
	RegisteredAt time.Time `json:"registered_at"` // Timestamp when the device was registered
}
