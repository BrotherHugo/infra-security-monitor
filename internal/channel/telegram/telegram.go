package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/BrotherHugo/infra-security-monitor/internal/domain"
)

const (
	channelName         = "telegram"
	telegramMaxLen      = 4096
	telegramAPIBase     = "https://api.telegram.org"
	maxHeaderTemplate   = "--- ISM report (part 999/999) ---\n"
)

// HTTPDoer performs HTTP requests (for test doubles).
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Channel sends the report via Telegram Bot API sendMessage.
type Channel struct {
	token           string
	chatID          string
	messageThreadID int
	client          HTTPDoer
	baseURL         string
}

// New creates a telegram channel. messageThreadID <= 0 means the field is omitted from the API.
func New(token, chatID string, messageThreadID int) *Channel {
	return &Channel{
		token:           token,
		chatID:          chatID,
		messageThreadID: messageThreadID,
		client:          http.DefaultClient,
		baseURL:         telegramAPIBase,
	}
}

// Name returns the channel name.
func (c *Channel) Name() string {
	return channelName
}

// SetHTTPClient overrides the HTTP client (tests only).
func (c *Channel) SetHTTPClient(client HTTPDoer) {
	if client != nil {
		c.client = client
	}
}

// SetBaseURL overrides the API base URL (tests only).
func (c *Channel) SetBaseURL(baseURL string) {
	if strings.TrimSpace(baseURL) != "" {
		c.baseURL = strings.TrimRight(baseURL, "/")
	}
}

// Send delivers the report Body; long text is split into chunks <= 4096 bytes.
func (c *Channel) Send(ctx context.Context, report domain.TextReport) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	messages := splitMessages(report.Body)
	for _, text := range messages {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := c.sendMessage(ctx, text); err != nil {
			return err
		}
	}
	return nil
}

func (c *Channel) sendMessage(ctx context.Context, text string) error {
	payload := sendMessageRequest{
		ChatID: c.chatID,
		Text:   text,
	}
	if c.messageThreadID > 0 {
		payload.MessageThreadID = c.messageThreadID
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("telegram channel: marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/bot%s/sendMessage", c.baseURL, c.token)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("telegram channel: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("telegram channel: http: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("telegram channel: read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("telegram channel: http status %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var apiResp sendMessageResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return fmt.Errorf("telegram channel: decode response: %w", err)
	}
	if !apiResp.OK {
		desc := strings.TrimSpace(apiResp.Description)
		if desc == "" {
			desc = "unknown error"
		}
		return fmt.Errorf("telegram channel: api error: %s", desc)
	}
	return nil
}

type sendMessageRequest struct {
	ChatID          string `json:"chat_id"`
	Text            string `json:"text"`
	MessageThreadID int    `json:"message_thread_id,omitempty"`
}

type sendMessageResponse struct {
	OK          bool   `json:"ok"`
	Description string `json:"description"`
}

func splitMessages(body string) []string {
	runes := []rune(body)
	if len(runes) <= telegramMaxLen {
		return []string{body}
	}

	maxHeaderRunes := len([]rune(maxHeaderTemplate))
	contMax := telegramMaxLen - maxHeaderRunes
	if contMax < 1 {
		contMax = 1
	}

	rest := len(runes) - telegramMaxLen
	total := 1 + (rest+contMax-1)/contMax

	for {
		messages := make([]string, 0, total)
		offset := 0

		end := minInt(telegramMaxLen, len(runes))
		messages = append(messages, string(runes[offset:end]))
		offset = end

		for part := 2; part <= total && offset < len(runes); part++ {
			header := fmt.Sprintf("--- ISM report (part %d/%d) ---\n", part, total)
			headerRunes := len([]rune(header))
			chunkMax := telegramMaxLen - headerRunes
			if chunkMax < 1 {
				chunkMax = 1
			}
			end = minInt(offset+chunkMax, len(runes))
			messages = append(messages, header+string(runes[offset:end]))
			offset = end
		}

		if offset >= len(runes) {
			return messages
		}
		total++
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
