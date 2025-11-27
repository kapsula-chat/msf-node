/*
 * Copyright (c) Kapsula, Inc., 2025
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/dgraph-io/badger/v4"
	"github.com/gin-gonic/gin"
)

const (
	MessageSize = 4096
)

func NewServer(dataDir string) *Server {
	ctx, cancel := context.WithCancel(context.Background())

	s := &Server{
		dataDir:  dataDir,
		shutdown: make(chan os.Signal, 1),
		ctx:      ctx,
		cancel:   cancel,
		badger: (func() *badger.DB {
			opts := badger.DefaultOptions(filepath.Join(dataDir, "messages", "storage.badger"))
			opts.Logger = nil                         // Disable badger logging
			opts.SyncWrites = true                    // Ensure writes are synced to disk
			opts.MemTableSize = 64 << 20              // 64MB memory buffer
			opts.ValueThreshold = 1024                // Values >1KB в value log
			opts.NumMemtables = 5                     // More memtables for writes
			opts.NumLevelZeroTables = 5               // Меньше Level 0 compaction
			opts.NumCompactors = runtime.NumCPU() - 1 // Use all but one CPU core for compaction
			db, err := badger.Open(opts)
			if err != nil {
				log.Fatalf("Failed to open Badger database: %v", err)
			}
			return db
		})(),
	}

	if err := s.initDirectories(); err != nil {
		log.Fatalf("Failed to initialize directories: %v", err)
	}

	s.setupRouter()

	signal.Notify(s.shutdown, os.Interrupt, syscall.SIGTERM)

	s.messages = make(chan RawMessage, 11000)
	go s.startWriter(s.badger, s.messages, &s.wg)

	// Start badger metrics collector
	go s.startBadgerCollector(30 * time.Second)

	return s
}

func (s *Server) initDirectories() error {

	if err := os.MkdirAll(s.dataDir, 0755); err != nil && !os.IsExist(err) {
		return fmt.Errorf("failed to create data directory %s: %w", s.dataDir, err)
	}

	dirs := []string{
		filepath.Join(s.dataDir, "messages"),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	return nil
}

func (s *Server) setupRouter() {
	if strings.ToUpper(os.Getenv("ENV")) == "PRODUCTION" {
		gin.SetMode(gin.ReleaseMode)
	} else {
		gin.SetMode(gin.DebugMode)
	}

	s.router = gin.New()
	s.router.Use(gin.Logger())
	s.router.Use(gin.Recovery())
	s.router.Use(s.requestSizeMiddleware())

	token := os.Getenv("KAPSULA_ACCESS_TOKEN")
	if token != "" {
		log.Printf("Access token: %s", token)
		s.router.Use(s.requestAuthMiddleware(token))
	}

	s.router.POST("/message", s.sendMessage)
	s.router.GET("/message", s.getMessages)
	s.router.GET("/device", s.listDevices)
	s.router.POST("/device", s.registerDevice)
	s.router.DELETE("/device", s.unregisterDevice)
	s.router.GET("/health", s.healthCheck)
}

func (s *Server) requestSizeMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.ContentLength > MessageSize {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{
				"error": "Request too large",
			})
			c.Abort()
			return
		}
		c.Next()
	}
}

func (s *Server) requestAuthMiddleware(token string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.URL.Path == "/message" && c.Request.Method == "POST" {
			// Allow unauthenticated message sending
			c.Next()
			return
		}
		authHeader := c.GetHeader("Authorization")
		if authHeader != fmt.Sprintf("Bearer %s", token) {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Unauthorized",
			})
			c.Abort()
			return
		}
		c.Next()
	}
}

func (s *Server) healthCheck(c *gin.Context) {
	// Expose a small set of Prometheus-format metrics so Netdata (or other
	// Prometheus-compatible scrapers) can collect them.
	// Metrics are intentionally lightweight and avoid expensive DB scans.

	// free disk space (bytes)
	var freeSpace uint64
	{
		var stat syscall.Statfs_t
		if err := syscall.Statfs(s.dataDir, &stat); err != nil {
			log.Printf("Failed to get filesystem stats: %v", err)
			freeSpace = 0
		} else {
			freeSpace = stat.Bavail * uint64(stat.Bsize)
		}
	}

	queued := 0
	if s.messages != nil {
		queued = len(s.messages)
	}

	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	goroutines := runtime.NumGoroutine()

	// Build Prometheus exposition text
	var b strings.Builder
	b.WriteString("# HELP kapsula_queued_messages Number of messages queued for writing\n")
	b.WriteString("# TYPE kapsula_queued_messages gauge\n")
	b.WriteString(fmt.Sprintf("kapsula_queued_messages %d\n", queued))

	b.WriteString("# HELP kapsula_goroutines Number of goroutines\n")
	b.WriteString("# TYPE kapsula_goroutines gauge\n")
	b.WriteString(fmt.Sprintf("kapsula_goroutines %d\n", goroutines))

	b.WriteString("# HELP kapsula_free_space_bytes Free disk space in data directory in bytes\n")
	b.WriteString("# TYPE kapsula_free_space_bytes gauge\n")
	b.WriteString(fmt.Sprintf("kapsula_free_space_bytes %d\n", freeSpace))

	b.WriteString("# HELP kapsula_mem_alloc_bytes Number of bytes allocated and still in use\n")
	b.WriteString("# TYPE kapsula_mem_alloc_bytes gauge\n")
	b.WriteString(fmt.Sprintf("kapsula_mem_alloc_bytes %d\n", mem.Alloc))

	b.WriteString("# HELP kapsula_mem_sys_bytes Number of bytes obtained from the system\n")
	b.WriteString("# TYPE kapsula_mem_sys_bytes gauge\n")
	b.WriteString(fmt.Sprintf("kapsula_mem_sys_bytes %d\n", mem.Sys))

	b.WriteString("# HELP kapsula_heap_alloc_bytes Bytes of allocated heap objects\n")
	b.WriteString("# TYPE kapsula_heap_alloc_bytes gauge\n")
	b.WriteString(fmt.Sprintf("kapsula_heap_alloc_bytes %d\n", mem.HeapAlloc))

	b.WriteString("# HELP kapsula_gc_count Number of completed GC cycles\n")
	b.WriteString("# TYPE kapsula_gc_count counter\n")
	b.WriteString(fmt.Sprintf("kapsula_gc_count %d\n", mem.NumGC))

	// Include cached badger metrics
	s.badgerMu.RLock()
	bTotal := s.badgerTotalSize
	bSst := s.badgerSSTFiles
	bVlog := s.badgerVlogFiles
	bLast := s.badgerLastObserved
	s.badgerMu.RUnlock()

	b.WriteString("# HELP kapsula_badger_total_size_bytes Total size of Badger files (bytes)\n")
	b.WriteString("# TYPE kapsula_badger_total_size_bytes gauge\n")
	b.WriteString(fmt.Sprintf("kapsula_badger_total_size_bytes %d\n", bTotal))

	b.WriteString("# HELP kapsula_badger_sst_files Number of .sst files\n")
	b.WriteString("# TYPE kapsula_badger_sst_files gauge\n")
	b.WriteString(fmt.Sprintf("kapsula_badger_sst_files %d\n", bSst))

	b.WriteString("# HELP kapsula_badger_vlog_files Number of .vlog files\n")
	b.WriteString("# TYPE kapsula_badger_vlog_files gauge\n")
	b.WriteString(fmt.Sprintf("kapsula_badger_vlog_files %d\n", bVlog))

	b.WriteString("# HELP kapsula_badger_last_observed_seconds Unix timestamp when badger metrics were collected\n")
	b.WriteString("# TYPE kapsula_badger_last_observed_seconds gauge\n")
	b.WriteString(fmt.Sprintf("kapsula_badger_last_observed_seconds %d\n", bLast.Unix()))

	// Keep the response content-type Prometheus expects
	c.Data(http.StatusOK, "text/plain; version=0.0.4; charset=utf-8", []byte(b.String()))
}

func (s *Server) startBadgerCollector(interval time.Duration) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				// Walk badger storage dir and compute sizes
				storageDir := filepath.Join(s.dataDir, "messages", "storage.badger")
				var total uint64
				var sstCount, vlogCount int
				_ = filepath.Walk(storageDir, func(path string, info os.FileInfo, err error) error {
					if err != nil {
						return nil
					}
					if info.IsDir() {
						return nil
					}
					total += uint64(info.Size())
					if strings.HasSuffix(path, ".sst") {
						sstCount++
					} else if strings.HasSuffix(path, ".vlog") || strings.HasSuffix(path, ".vlog") {
						vlogCount++
					}
					return nil
				})

				s.badgerMu.Lock()
				s.badgerTotalSize = total
				s.badgerSSTFiles = sstCount
				s.badgerVlogFiles = vlogCount
				s.badgerLastObserved = time.Now().UTC()
				s.badgerMu.Unlock()

				// Generate Netdata mapping YAML
				mappingDir := filepath.Join(s.dataDir, "netdata")
				_ = os.MkdirAll(mappingDir, 0755)
				mapPath := filepath.Join(mappingDir, "kapsula-prometheus-mapping.yaml")

				mapping := map[string]any{
					"name": "kapsula",
					"metrics": []map[string]any{
						{"name": "kapsula_queued_messages", "id": "queued_messages", "type": "gauge", "units": "messages"},
						{"name": "kapsula_goroutines", "id": "goroutines", "type": "gauge", "units": "count"},
						{"name": "kapsula_free_space_bytes", "id": "free_space", "type": "gauge", "units": "bytes"},
						{"name": "kapsula_mem_alloc_bytes", "id": "mem_alloc_bytes", "type": "gauge", "units": "bytes"},
						{"name": "kapsula_heap_alloc_bytes", "id": "heap_alloc_bytes", "type": "gauge", "units": "bytes"},
						{"name": "kapsula_gc_count", "id": "gc_count", "type": "counter", "units": "count"},
						{"name": "kapsula_badger_total_size_bytes", "id": "badger_total_size", "type": "gauge", "units": "bytes"},
						{"name": "kapsula_badger_sst_files", "id": "badger_sst_files", "type": "gauge", "units": "count"},
						{"name": "kapsula_badger_vlog_files", "id": "badger_vlog_files", "type": "gauge", "units": "count"},
					},
				}

				f, err := os.Create(mapPath)
				if err == nil {
					enc := yaml.NewEncoder(f)
					_ = enc.Encode(mapping)
					_ = f.Close()
				}

			case <-s.ctx.Done():
				return
			}
		}
	}()
}

func (s *Server) Start() error {
	// Create an HTTP server
	srv := &http.Server{
		Addr:    ":8080",
		Handler: s.router,
	}

	// Goroutine for graceful shutdown
	go func() {
		// Wait for a shutdown signal
		sig := <-s.shutdown
		log.Printf("Received signal: %v, shutting down...", sig)
		// Cancel the context to stop background tasks
		s.cancel()
		if err := s.badger.Close(); err != nil {
			log.Printf("Failed to close Badger DB: %v", err)
		}

		// Create context with timeout for shutdown
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Try to gracefully shut down the server
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("Server forced to shutdown: %v", err)
		}

		// Wait for all goroutines to finish
		s.wg.Wait()
		log.Println("Clean shutdown completed")
	}()

	log.Printf("Starting server on :8080 with data directory: %s", s.dataDir)

	// Run the server (blocking call)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}

	// Return nil on graceful shutdown
	return nil
}

func main() {
	dataDir := "/data"
	if strings.ToUpper(os.Getenv("ENV")) != "PRODUCTION" {
		dataDir = "./data"
	}

	server := NewServer(dataDir)
	if err := server.Start(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
