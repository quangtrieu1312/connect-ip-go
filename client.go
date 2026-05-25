package connectip

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

// Dial dials a proxied connection to a target server.
func Dial(ctx context.Context, conn *http3.ClientConn, template *uritemplate.Template) (*Conn, *http.Response, error) {
	return DialWithHeaders(ctx, conn, template, nil)
}

// DialWithHeaders is like Dial but merges extra request headers into the
// CONNECT-IP request (e.g. application-specific tunnel coordinates). The
// capsule-protocol header is always set and cannot be overridden.
func DialWithHeaders(ctx context.Context, conn *http3.ClientConn, template *uritemplate.Template, extra http.Header) (*Conn, *http.Response, error) {
	if len(template.Varnames()) > 0 {
		return nil, nil, errors.New("connect-ip: IP flow forwarding not supported")
	}

	u, err := url.Parse(template.Raw())
	if err != nil {
		return nil, nil, fmt.Errorf("connect-ip: failed to parse URI: %w", err)
	}

	select {
	case <-ctx.Done():
		return nil, nil, context.Cause(ctx)
	case <-conn.Context().Done():
		return nil, nil, context.Cause(conn.Context())
	case <-conn.ReceivedSettings():
	}
	settings := conn.Settings()
	if !settings.EnableExtendedConnect {
		return nil, nil, errors.New("connect-ip: server didn't enable Extended CONNECT")
	}
	if !settings.EnableDatagrams {
		return nil, nil, errors.New("connect-ip: server didn't enable datagrams")
	}

	rstr, err := conn.OpenRequestStream(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("connect-ip: failed to open request stream: %w", err)
	}
	hdr := http.Header{http3.CapsuleProtocolHeader: []string{capsuleProtocolHeaderValue}}
	for k, vs := range extra {
		if k == http3.CapsuleProtocolHeader {
			continue
		}
		for _, v := range vs {
			hdr.Add(k, v)
		}
	}
	if err := rstr.SendRequestHeader(&http.Request{
		Method: http.MethodConnect,
		Proto:  requestProtocol,
		Host:   u.Host,
		Header: hdr,
		URL:    u,
	}); err != nil {
		return nil, nil, fmt.Errorf("connect-ip: failed to send request: %w", err)
	}
	// TODO: optimistically return the connection
	rsp, err := rstr.ReadResponse()
	if err != nil {
		return nil, nil, fmt.Errorf("connect-ip: failed to read response: %w", err)
	}
	if rsp.StatusCode < 200 || rsp.StatusCode > 299 {
		return nil, rsp, fmt.Errorf("connect-ip: server responded with %d", rsp.StatusCode)
	}
	return newProxiedConn(rstr), rsp, nil
}
