package app

import (
	"fmt"
	"strings"
	"time"

	emailchannel "github.com/BrotherHugo/infra-security-monitor/internal/channel/email"
	filechannel "github.com/BrotherHugo/infra-security-monitor/internal/channel/file"
	telegramchannel "github.com/BrotherHugo/infra-security-monitor/internal/channel/telegram"
	"github.com/BrotherHugo/infra-security-monitor/internal/config"
	"github.com/BrotherHugo/infra-security-monitor/internal/service/report"
)

func loadLocation(timezone string) (*time.Location, error) {
	if strings.TrimSpace(timezone) == "" {
		return time.Local, nil
	}
	loc, err := time.LoadLocation(timezone)
	if err != nil {
		return nil, fmt.Errorf("timezone %q: %w", timezone, err)
	}
	return loc, nil
}

// BuildChannels builds delivery channels from reporting.channels (order: file -> telegram -> email).
func BuildChannels(cfg config.Config, loc *time.Location) ([]report.Sender, error) {
	channels := make([]report.Sender, 0, 3)

	if cfg.Reporting.Channels.File != nil {
		channels = append(channels, filechannel.New(cfg.Reporting.Channels.File.SaveToDir, loc))
	}
	if cfg.Reporting.Channels.Telegram != nil {
		ch := cfg.Reporting.Channels.Telegram
		messageThreadID := 0
		if ch.MessageThreadID != nil {
			messageThreadID = *ch.MessageThreadID
		}
		channels = append(channels, telegramchannel.New(ch.Token, ch.ChatID, messageThreadID))
	}
	if cfg.Reporting.Channels.Email != nil {
		ch := cfg.Reporting.Channels.Email
		emailCh, err := emailchannel.New(emailchannel.HostConfig{
			Host:      ch.Host,
			Port:      ch.Port,
			User:      ch.User,
			Password:  ch.Password,
			UseTLS:    ch.UseTLS,
			UseSSL:    ch.UseSSL,
			FromEmail: ch.FromEmail,
			ToEmails:  ch.ToEmails,
		}, loc)
		if err != nil {
			return nil, err
		}
		channels = append(channels, emailCh)
	}
	if len(channels) == 0 {
		return nil, fmt.Errorf("no channels configured")
	}

	return channels, nil
}
