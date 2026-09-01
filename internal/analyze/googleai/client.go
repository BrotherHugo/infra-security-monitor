package googleai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const temperature = 0.2

type generateContentRequest struct {
	SystemInstruction systemInstruction   `json:"systemInstruction"`
	Contents          []content           `json:"contents"`
	GenerationConfig  generationConfig    `json:"generationConfig"`
}

type systemInstruction struct {
	Parts []textPart `json:"parts"`
}

type content struct {
	Role  string     `json:"role"`
	Parts []textPart `json:"parts"`
}

type textPart struct {
	Text string `json:"text"`
}

type generationConfig struct {
	Temperature float64 `json:"temperature"`
}

type generateContentResponse struct {
	Candidates []struct {
		Content struct {
			Parts []struct {
				Text string `json:"text"`
			} `json:"parts"`
		} `json:"content"`
	} `json:"candidates"`
	PromptFeedback struct {
		BlockReason string `json:"blockReason"`
	} `json:"promptFeedback"`
}

type apiErrorResponse struct {
	Error struct {
		Message string `json:"message"`
	} `json:"error"`
}

func (a *Analyzer) generateContent(ctx context.Context, systemPrompt, userPayload string) (string, error) {
	reqBody := generateContentRequest{
		SystemInstruction: systemInstruction{
			Parts: []textPart{{Text: systemPrompt}},
		},
		Contents: []content{
			{
				Role:  "user",
				Parts: []textPart{{Text: userPayload}},
			},
		},
		GenerationConfig: generationConfig{Temperature: temperature},
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("gemini API: marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/v1beta/models/%s:generateContent", a.baseURL, a.model)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("gemini API: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-goog-api-key", a.apiKey)

	resp, err := a.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("gemini API: http: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("gemini API: read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", httpStatusError(resp.StatusCode, respBody)
	}

	var apiResp generateContentResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return "", fmt.Errorf("gemini API: decode response: %w", err)
	}
	if reason := strings.TrimSpace(apiResp.PromptFeedback.BlockReason); reason != "" {
		return "", fmt.Errorf("gemini API: prompt blocked: %s", reason)
	}
	if len(apiResp.Candidates) == 0 {
		return "", fmt.Errorf("gemini API: empty candidates")
	}

	var parts []string
	for _, part := range apiResp.Candidates[0].Content.Parts {
		if text := strings.TrimSpace(part.Text); text != "" {
			parts = append(parts, text)
		}
	}
	if len(parts) == 0 {
		return "", fmt.Errorf("gemini API: empty candidate text")
	}
	return strings.Join(parts, "\n"), nil
}

func httpStatusError(statusCode int, body []byte) error {
	var apiErr apiErrorResponse
	if err := json.Unmarshal(body, &apiErr); err == nil {
		if msg := strings.TrimSpace(apiErr.Error.Message); msg != "" {
			return fmt.Errorf("gemini API: %s", msg)
		}
	}
	raw := strings.TrimSpace(string(body))
	if len(raw) > 512 {
		raw = raw[:512]
	}
	if raw == "" {
		return fmt.Errorf("gemini API: HTTP %d", statusCode)
	}
	return fmt.Errorf("gemini API: HTTP %d: %s", statusCode, raw)
}
