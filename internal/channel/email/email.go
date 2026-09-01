package email

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"

	"github.com/BrotherHugo/infra-security-monitor/internal/domain"
)

const channelName = "email"

// deliverFunc delivers a MIME message.
type deliverFunc func(ctx context.Context, msg []byte) error

func (f deliverFunc) Deliver(ctx context.Context, msg []byte) error {
	return f(ctx, msg)
}

// Channel sends the report via SMTP.
type Channel struct {
	host      string
	port      string
	user      string
	password  string
	useTLS    bool
	useSSL    bool
	fromEmail string
	toEmails  []string
	location  *time.Location
	deliver   deliverFunc
}

// New creates an email channel.
func New(cfg HostConfig, location *time.Location) (*Channel, error) {
	loc := location
	if loc == nil {
		loc = time.Local
	}
	ch := &Channel{
		host:      cfg.Host,
		port:      cfg.Port,
		user:      cfg.User,
		password:  cfg.Password,
		useTLS:    cfg.UseTLS,
		useSSL:    cfg.UseSSL,
		fromEmail: cfg.FromEmail,
		toEmails:  append([]string(nil), cfg.ToEmails...),
		location:  loc,
	}
	ch.deliver = deliverFunc(ch.deliverSMTP)
	return ch, nil
}

// HostConfig holds SMTP parameters for the channel.
type HostConfig struct {
	Host      string
	Port      string
	User      string
	Password  string
	UseTLS    bool
	UseSSL    bool
	FromEmail string
	ToEmails  []string
}

// Name returns the channel name.
func (c *Channel) Name() string {
	return channelName
}

// SetDeliverer overrides delivery (tests only).
func (c *Channel) SetDeliverer(fn func(ctx context.Context, msg []byte) error) {
	if fn != nil {
		c.deliver = deliverFunc(fn)
	}
}

// Send delivers the report Body as MIME text/plain.
func (c *Channel) Send(ctx context.Context, report domain.TextReport) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	msg, err := c.buildMessage(report)
	if err != nil {
		return err
	}
	return c.deliver.Deliver(ctx, msg)
}

func (c *Channel) buildMessage(report domain.TextReport) ([]byte, error) {
	ts := report.GeneratedAt
	if ts.IsZero() {
		ts = time.Now()
	}
	localTS := ts.In(c.location)
	subject := fmt.Sprintf("ISM report: %s %s", report.Hostname, localTS.Format("2006-01-02 15:04:05"))

	var buf bytes.Buffer
	writeHeader(&buf, "From", c.fromEmail)
	for _, to := range c.toEmails {
		writeHeader(&buf, "To", to)
	}
	writeHeader(&buf, "Subject", subject)
	buf.WriteString("MIME-Version: 1.0\r\n")
	buf.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	buf.WriteString("Content-Transfer-Encoding: 8bit\r\n")
	buf.WriteString("\r\n")
	buf.WriteString(normalizeCRLF(report.Body))
	if !strings.HasSuffix(buf.String(), "\r\n") {
		buf.WriteString("\r\n")
	}
	return buf.Bytes(), nil
}

func writeHeader(buf *bytes.Buffer, key, value string) {
	buf.WriteString(key)
	buf.WriteString(": ")
	buf.WriteString(value)
	buf.WriteString("\r\n")
}

func normalizeCRLF(body string) string {
	body = strings.ReplaceAll(body, "\r\n", "\n")
	body = strings.ReplaceAll(body, "\r", "\n")
	return strings.ReplaceAll(body, "\n", "\r\n")
}

func (c *Channel) deliverSMTP(ctx context.Context, msg []byte) error {
	addr := net.JoinHostPort(c.host, c.port)
	auth := smtp.PlainAuth("", c.user, c.password, c.host)

	if c.useSSL {
		return c.deliverSSL(ctx, addr, auth, msg)
	}
	if c.useTLS {
		return c.deliverSTARTTLS(ctx, addr, auth, msg)
	}
	return c.deliverPlain(ctx, addr, auth, msg)
}

func (c *Channel) deliverPlain(ctx context.Context, addr string, auth smtp.Auth, msg []byte) error {
	done := make(chan error, 1)
	go func() {
		done <- smtp.SendMail(addr, auth, c.fromEmail, c.toEmails, msg)
	}()

	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("email channel: smtp: %w", err)
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Channel) deliverSTARTTLS(ctx context.Context, addr string, auth smtp.Auth, msg []byte) error {
	client, err := c.dialSMTP(ctx, addr, false)
	if err != nil {
		return err
	}
	defer client.Close()

	if ok, _ := client.Extension("STARTTLS"); !ok {
		return fmt.Errorf("email channel: smtp server %q does not support STARTTLS", addr)
	}
	if err := client.StartTLS(&tls.Config{ServerName: c.host}); err != nil {
		return fmt.Errorf("email channel: starttls: %w", err)
	}
	if err := c.submitMessage(client, auth, msg); err != nil {
		return err
	}
	return client.Quit()
}

func (c *Channel) deliverSSL(ctx context.Context, addr string, auth smtp.Auth, msg []byte) error {
	client, err := c.dialSMTP(ctx, addr, true)
	if err != nil {
		return err
	}
	defer client.Close()

	if err := c.submitMessage(client, auth, msg); err != nil {
		return err
	}
	return client.Quit()
}

func (c *Channel) dialSMTP(ctx context.Context, addr string, ssl bool) (*smtp.Client, error) {
	type dialResult struct {
		client *smtp.Client
		err    error
	}
	done := make(chan dialResult, 1)
	go func() {
		if ssl {
			conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: c.host})
			if err != nil {
				done <- dialResult{err: err}
				return
			}
			client, err := smtp.NewClient(conn, c.host)
			done <- dialResult{client: client, err: err}
			return
		}
		client, err := smtp.Dial(addr)
		done <- dialResult{client: client, err: err}
	}()

	select {
	case res := <-done:
		if res.err != nil {
			return nil, fmt.Errorf("email channel: dial %q: %w", addr, res.err)
		}
		return res.client, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *Channel) submitMessage(client *smtp.Client, auth smtp.Auth, msg []byte) error {
	if auth != nil {
		if ok, _ := client.Extension("AUTH"); ok {
			if err := client.Auth(auth); err != nil {
				return fmt.Errorf("email channel: auth: %w", err)
			}
		}
	}
	if err := client.Mail(c.fromEmail); err != nil {
		return fmt.Errorf("email channel: mail from: %w", err)
	}
	for _, to := range c.toEmails {
		if err := client.Rcpt(to); err != nil {
			return fmt.Errorf("email channel: rcpt %q: %w", to, err)
		}
	}
	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("email channel: data: %w", err)
	}
	if _, err := writer.Write(msg); err != nil {
		_ = writer.Close()
		return fmt.Errorf("email channel: write body: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("email channel: close data: %w", err)
	}
	return nil
}
