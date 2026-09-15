// Package telegram is a small Bot API client for the standalone panel:
// alerts (doctor failures, cores down) to one chat, and /status on demand.
package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// APIBase is the Bot API root; tests point it elsewhere.
var APIBase = "https://api.telegram.org"

// Client calls one bot.
type Client struct {
	Token string
	HTTP  *http.Client
}

func (c *Client) call(ctx context.Context, method string, params any, out any) error {
	body, _ := json.Marshal(params)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, APIBase+"/bot"+c.Token+"/"+method, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 60 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var env struct {
		OK          bool            `json:"ok"`
		Description string          `json:"description"`
		Result      json.RawMessage `json:"result"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&env); err != nil {
		return fmt.Errorf("telegram %s: %w", method, err)
	}
	if !env.OK {
		return fmt.Errorf("telegram %s: %s", method, env.Description)
	}
	if out != nil {
		return json.Unmarshal(env.Result, out)
	}
	return nil
}

// Me returns the bot's username (a token check).
func (c *Client) Me(ctx context.Context) (string, error) {
	var me struct {
		Username string `json:"username"`
	}
	err := c.call(ctx, "getMe", map[string]any{}, &me)
	return me.Username, err
}

// Send posts an HTML message.
func (c *Client) Send(ctx context.Context, chatID int64, text string) error {
	return c.call(ctx, "sendMessage", map[string]any{"chat_id": chatID, "text": text, "parse_mode": "HTML", "disable_web_page_preview": true}, nil)
}

// Update is the subset of a Bot API update we act on.
type Update struct {
	ID      int64 `json:"update_id"`
	Message *struct {
		Text string `json:"text"`
		Chat struct {
			ID int64 `json:"id"`
		} `json:"chat"`
	} `json:"message"`
}

func (c *Client) updates(ctx context.Context, offset int64, timeout int) ([]Update, error) {
	var out []Update
	err := c.call(ctx, "getUpdates", map[string]any{"offset": offset, "timeout": timeout, "allowed_updates": []string{"message"}}, &out)
	return out, err
}

// Settings is what the bot needs; re-read on every use so the panel's
// settings page takes effect without a restart.
type Settings struct {
	Token  string
	ChatID int64
	Notify bool
}

// Bot polls for commands and delivers alerts.
type Bot struct {
	Settings func() Settings
	// Status renders the /status reply (HTML).
	Status func(ctx context.Context) string
	Log    *slog.Logger
	// PollTimeout is the long-poll wait in seconds (tests lower it).
	PollTimeout int

	offset int64
}

// Notify sends an alert to the configured chat when notifications are on.
func (b *Bot) Notify(ctx context.Context, text string) error {
	s := b.Settings()
	if s.Token == "" || s.ChatID == 0 || !s.Notify {
		return nil
	}
	return (&Client{Token: s.Token}).Send(ctx, s.ChatID, text)
}

// Run polls until ctx ends. /status answers with Status(); /start or /id
// tells the sender its chat id so it can be pasted into the settings.
func (b *Bot) Run(ctx context.Context) {
	log := b.Log
	if log == nil {
		log = slog.Default()
	}
	log = log.With("component", "telegram")
	timeout := b.PollTimeout
	if timeout <= 0 {
		timeout = 30
	}
	for ctx.Err() == nil {
		s := b.Settings()
		if s.Token == "" {
			select {
			case <-ctx.Done():
				return
			case <-time.After(15 * time.Second):
			}
			continue
		}
		c := &Client{Token: s.Token, HTTP: &http.Client{Timeout: time.Duration(timeout+15) * time.Second}}
		ups, err := c.updates(ctx, b.offset, timeout)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Warn("poll", "err", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(10 * time.Second):
			}
			continue
		}
		for _, u := range ups {
			b.offset = u.ID + 1
			if u.Message == nil {
				continue
			}
			cmd := strings.ToLower(strings.TrimSpace(u.Message.Text))
			if i := strings.Index(cmd, "@"); i > 0 {
				cmd = cmd[:i]
			}
			chat := u.Message.Chat.ID
			var reply string
			switch cmd {
			case "/start", "/id":
				reply = fmt.Sprintf("bosun bot. Your chat id: <code>%d</code>", chat)
			case "/status":
				if s.ChatID != 0 && chat != s.ChatID {
					reply = "not your node"
				} else if b.Status != nil {
					reply = b.Status(ctx)
				}
			default:
				continue
			}
			if reply != "" {
				if err := c.Send(ctx, chat, reply); err != nil {
					log.Warn("reply", "err", err)
				}
			}
		}
	}
}
