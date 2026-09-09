package model

import (
	"fmt"
	"net"
	"strconv"
)

type Mode string

const (
	ModeHost Mode = "host"
	ModeSNI  Mode = "sni"
)

type Target struct {
	Scheme, ConnectHost, OriginalHost, OriginalSNI, Raw string
	Port                                                int
}

func (t Target) Address() string { return net.JoinHostPort(t.ConnectHost, strconv.Itoa(t.Port)) }
func (t Target) Display() string { return fmt.Sprintf("%s://%s", t.Scheme, t.Address()) }

type Probe struct {
	Target Target
	VHost  string
	Mode   Mode
}

type Fingerprint struct {
	StatusCode       int      `json:"status_code"`
	ContentLength    int64    `json:"content_length"`
	BodyHash         string   `json:"body_hash,omitempty"`
	Title            string   `json:"title,omitempty"`
	Location         string   `json:"location,omitempty"`
	ContentType      string   `json:"content_type,omitempty"`
	Server           string   `json:"server,omitempty"`
	CertificateHash  string   `json:"certificate_hash,omitempty"`
	CertificateNames []string `json:"certificate_names,omitempty"`
}

type Result struct {
	Target string `json:"target"`
	VHost  string `json:"vhost"`
	Mode   Mode   `json:"mode"`
	Fingerprint
	Classification string `json:"classification"`
	BaselineStatus int    `json:"baseline_status,omitempty"`
	BaselineLength int64  `json:"baseline_length,omitempty"`
	Error          string `json:"error,omitempty"`
}
