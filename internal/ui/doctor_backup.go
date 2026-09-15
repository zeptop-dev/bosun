package ui

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"time"

	"github.com/zeptop-dev/bosun/internal/backup"
	"github.com/zeptop-dev/bosun/internal/doctor"
	"github.com/zeptop-dev/bosun/pkg/agentproto"
)

// Doctor on demand (cached 30 s) and standalone backup/restore.

func (s *Server) doctorBackupRoutes() {
	m := s.mux
	auth := s.requireAuth
	m.HandleFunc("GET /api/doctor", auth(s.getDoctor))
	m.HandleFunc("POST /api/reality/scan", auth(s.realityScan))
	m.HandleFunc("GET /api/backup", auth(s.getBackup))
	m.HandleFunc("POST /api/backup/restore", auth(s.local(s.restoreBackup)))
}

const doctorCache = 30 * time.Second

func (s *Server) getDoctor(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	// ?fresh=1 (the UI's "run again") bypasses the cache.
	if r.URL.Query().Get("fresh") == "" && s.doctorAt.Add(doctorCache).After(time.Now()) && s.doctorRep != nil {
		rep := *s.doctorRep
		s.mu.Unlock()
		ok(w, rep)
		return
	}
	s.mu.Unlock()
	var rep agentproto.DoctorReport
	if a := s.currentAgent(); a != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		rep = a.Doctor(ctx)
	} else {
		rep = doctor.Run(r.Context(), doctor.Deps{})
	}
	s.mu.Lock()
	s.doctorRep, s.doctorAt = &rep, time.Now()
	s.mu.Unlock()
	ok(w, rep)
}

func (s *Server) dataDir() string { return filepath.Dir(s.d.Store.Path()) }

func (s *Server) getBackup(w http.ResponseWriter, r *http.Request) {
	name := backup.Name(time.Now())
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", "attachment; filename="+name)
	if err := backup.Write(s.dataDir(), w); err != nil {
		s.d.Log.Error("backup", "err", err)
	}
}

// restoreBackup replaces the standalone configuration with an archive and
// reloads the store; the archive's admin login wins.
func (s *Server) restoreBackup(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(96 << 20); err != nil {
		fail(w, http.StatusBadRequest, errors.New("multipart form with a file field required"))
		return
	}
	f, _, err := r.FormFile("file")
	if err != nil {
		fail(w, http.StatusBadRequest, errors.New("file field required"))
		return
	}
	defer f.Close()
	sum, rollback, err := backup.Restore(s.dataDir(), f, s.d.Store.AdminKey())
	if err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	if err := s.d.Store.Reload(); err != nil {
		// The archive parsed but the store rejects it: put the previous
		// files back and reload those, so the node keeps running as before.
		rbErr := rollback()
		if rbErr == nil {
			rbErr = s.d.Store.Reload()
		}
		if rbErr != nil {
			fail(w, http.StatusInternalServerError, fmt.Errorf("restore failed (%v) and rollback failed too (%v)", err, rbErr))
			return
		}
		fail(w, http.StatusBadRequest, fmt.Errorf("restore rejected, previous configuration kept: %w", err))
		return
	}
	if sum.AdminChanged {
		// Sessions belong to the previous login.
		s.sessions.Clear()
	}
	ok(w, sum)
}
