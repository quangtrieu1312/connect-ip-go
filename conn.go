package connectip

import (
	"context"
	"encoding/binary"
	"errors"
	"expvar"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

// Reorder counters at ReceiveDatagram return in ReadPacket (post-http3 stream queue,
// pre-connect-ip context parse). Compared against quic-go dg_rcvout (upstream) and
// post-ReadPacket main.go (downstream) to localize where the residual client-side
// download reorder enters.
var (
	cipRecvTotal   = expvar.NewInt("cip_recv_total")
	cipRecvGenuine = expvar.NewInt("cip_recv_genuine")
	cipRecvRetr    = expvar.NewInt("cip_recv_retr")
)

const cipRingSize = 1024

type cipFlow struct {
	maxSeq uint32
	ring   [cipRingSize]uint32
	in     map[uint32]struct{}
	head   int
	count  int
}

// cipObs is touched only by the ReadPacket caller (one goroutine per connect-ip
// Conn = one tunnel reader) so it needs no lock.
type cipObs struct {
	flows map[[13]byte]*cipFlow
}

func newCipObs() *cipObs { return &cipObs{flows: make(map[[13]byte]*cipFlow)} }

// observe takes the [contextID varint][IP] payload that ReceiveDatagram returns
// inside ReadPacket. Skips one varint then parses IPv4+TCP seq + 5-tuple key.
func (o *cipObs) observe(p []byte) {
	if len(p) < 1 {
		return
	}
	off := 1 << (p[0] >> 6)
	if off >= len(p) {
		return
	}
	ip := p[off:]
	if len(ip) < 20 || ip[0]>>4 != 4 {
		return
	}
	ihl := int(ip[0]&0x0f) * 4
	if ihl < 20 || len(ip) < ihl+8 || ip[9] != 6 {
		return
	}
	tcp := ip[ihl:]
	seq := binary.BigEndian.Uint32(tcp[4:8])
	var key [13]byte
	copy(key[0:4], ip[12:16])
	copy(key[4:8], ip[16:20])
	copy(key[8:12], tcp[0:4])
	key[12] = 6
	cipRecvTotal.Add(1)
	f, exists := o.flows[key]
	if !exists {
		if len(o.flows) >= 256 {
			o.flows = make(map[[13]byte]*cipFlow)
		}
		f = &cipFlow{in: make(map[uint32]struct{}, cipRingSize)}
		o.flows[key] = f
	}
	if _, dup := f.in[seq]; dup {
		cipRecvRetr.Add(1)
		return
	}
	if f.count == cipRingSize {
		delete(f.in, f.ring[f.head])
	} else {
		f.count++
	}
	f.ring[f.head] = seq
	f.head = (f.head + 1) % cipRingSize
	f.in[seq] = struct{}{}
	if f.count == 1 || int32(seq-f.maxSeq) >= 0 {
		f.maxSeq = seq
		return
	}
	cipRecvGenuine.Add(1)
}

type CloseError struct {
	Remote bool
}

func (e *CloseError) Error() string        { return net.ErrClosed.Error() }
func (e *CloseError) Is(target error) bool { return target == net.ErrClosed }

type appendable interface{ append([]byte) []byte }

type writeCapsule struct {
	capsule appendable
	result  chan error
}

const (
	ipProtoICMP   = 1
	ipProtoICMPv6 = 58
)

type http3Stream interface {
	io.ReadWriteCloser
	ReceiveDatagram(context.Context) ([]byte, error)
	SendDatagram([]byte) error
	CancelRead(quic.StreamErrorCode)
}

var (
	_ http3Stream = &http3.Stream{}
	_ http3Stream = &http3.RequestStream{}
)

// If a packet is too large to fit into a QUIC datagram,
// we send an ICMP Packet Too Big packet.
// On IPv6, the minimum MTU of a link is 1280 bytes.
const minMTU = 1280

// Conn is a connection that proxies IP packets over HTTP/3.
type Conn struct {
	str    http3Stream
	writes chan writeCapsule

	assignedAddressNotify chan struct{}
	availableRoutesNotify chan struct{}

	mu                sync.Mutex
	peerAddresses     []netip.Prefix // IP prefixes that we assigned to the peer
	localRoutes       []IPRoute      // IP routes that we advertised to the peer
	assignedAddresses []netip.Prefix
	availableRoutes   []IPRoute

	closeChan chan struct{}
	closeErr  error

	// sendSeq is the per-connection monotonic counter stamped into sequenced
	// datagrams (contextIDSeq). Atomic because WritePacket may be called from
	// multiple goroutines for one Conn (the client hashes TUN queues to tunnels);
	// a single inner flow still maps to one caller, so its packets stay monotone.
	sendSeq atomic.Uint32

	// Receive reorder state for sequenced datagrams. Accessed ONLY by the single
	// ReadPacket consumer goroutine (one reader per Conn), so it needs no lock.
	// rcvInit becomes true on the first sequenced packet; rcvNextSeq is the next
	// seq to deliver; rcvBuf holds out-of-order payloads (copied, owned) keyed by
	// seq, bounded by reorderWindow. Because datagrams are never retransmitted in
	// this fork, a missing seq is skipped once the window fills (gap-skip) rather
	// than waited on forever.
	rcvInit    bool
	rcvNextSeq uint32
	rcvBuf     map[uint32][]byte

	// Seen-set genuine-reorder observer at ReceiveDatagram return (post-http3
	// stream queue). Single-goroutine = ReadPacket caller, no lock.
	recvObs *cipObs
}

// reorderWindow bounds how far out of order the receive buffer will hold packets
// before it gives up on a missing seq and skips the gap. Sized for the observed
// adjacent-swap reorder (a few packets) with headroom; larger = more reorder
// tolerance but more added latency / cross-flow head-of-line when a real gap hits.
const reorderWindow = 128

// seqAfter reports whether a is strictly after b in 32-bit wraparound order.
func seqAfter(a, b uint32) bool { return int32(a-b) > 0 }

func newProxiedConn(str http3Stream) *Conn {
	c := &Conn{
		str:                   str,
		writes:                make(chan writeCapsule),
		assignedAddressNotify: make(chan struct{}, 1),
		availableRoutesNotify: make(chan struct{}, 1),
		closeChan:             make(chan struct{}),
		rcvBuf:                make(map[uint32][]byte),
		recvObs:               newCipObs(),
	}
	go func() {
		if err := c.readFromStream(); err != nil {
			log.Printf("handling stream failed: %v", err)
			c.mu.Lock()
			if c.closeErr == nil {
				c.closeErr = &CloseError{Remote: true}
				close(c.closeChan)
			}
			c.mu.Unlock()
		}
	}()
	go func() {
		if err := c.writeToStream(); err != nil {
			log.Printf("writing to stream failed: %v", err)
			c.mu.Lock()
			if c.closeErr == nil {
				c.closeErr = &CloseError{Remote: true}
				close(c.closeChan)
			}
			c.mu.Unlock()
		}
	}()
	return c
}

// AdvertiseRoute informs the peer about available routes.
// This function can be called multiple times, but only the routes from the most recent call will be active.
// Previous route advertisements are overwritten by each new call to this function.
func (c *Conn) AdvertiseRoute(ctx context.Context, routes []IPRoute) error {
	for _, route := range routes {
		if route.StartIP.Compare(route.EndIP) == 1 {
			return fmt.Errorf("invalid route advertising start_ip: %s larger than %s", route.StartIP, route.EndIP)
		}
	}
	c.mu.Lock()
	c.localRoutes = slices.Clone(routes)
	c.mu.Unlock()
	return c.sendCapsule(ctx, &routeAdvertisementCapsule{IPAddressRanges: routes})
}

// AssignAddresses assigned address prefixes to the peer.
// This function can be called multiple times, but only the addresses from the most recent call will be active.
// Previous address assignments are overwritten by each new call to this function.
func (c *Conn) AssignAddresses(ctx context.Context, prefixes []netip.Prefix) error {
	c.mu.Lock()
	c.peerAddresses = slices.Clone(prefixes)
	c.mu.Unlock()
	capsule := &addressAssignCapsule{AssignedAddresses: make([]AssignedAddress, 0, len(prefixes))}
	for _, p := range prefixes {
		capsule.AssignedAddresses = append(capsule.AssignedAddresses, AssignedAddress{IPPrefix: p})
	}
	return c.sendCapsule(ctx, capsule)
}

func (c *Conn) sendCapsule(ctx context.Context, capsule appendable) error {
	res := make(chan error, 1)
	select {
	case c.writes <- writeCapsule{
		capsule: capsule,
		result:  res,
	}:
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-res:
			return err
		}
	case <-c.closeChan:
		return c.closeErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

// LocalPrefixes returns the prefixes that the peer currently assigned.
// Note that at any point during the connection, the peer can change the assignment.
// It is therefore recommended to call this function in a loop.
func (c *Conn) LocalPrefixes(ctx context.Context) ([]netip.Prefix, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closeChan:
		return nil, c.closeErr
	case <-c.assignedAddressNotify:
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.assignedAddresses, nil
	}
}

// Routes returns the routes that the peer currently advertised.
// Note that at any point during the connection, the peer can change the advertised routes.
// It is therefore recommended to call this function in a loop.
func (c *Conn) Routes(ctx context.Context) ([]IPRoute, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closeChan:
		return nil, c.closeErr
	case <-c.availableRoutesNotify:
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.availableRoutes, nil
	}
}

func (c *Conn) readFromStream() error {
	defer c.str.Close()
	r := quicvarint.NewReader(c.str)
	for {
		t, cr, err := http3.ParseCapsule(r)
		if err != nil {
			return err
		}
		switch t {
		case capsuleTypeAddressAssign:
			capsule, err := parseAddressAssignCapsule(cr)
			if err != nil {
				return err
			}
			prefixes := make([]netip.Prefix, 0, len(capsule.AssignedAddresses))
			for _, assigned := range capsule.AssignedAddresses {
				prefixes = append(prefixes, assigned.IPPrefix)
			}
			c.mu.Lock()
			c.assignedAddresses = prefixes
			c.mu.Unlock()
			select {
			case c.assignedAddressNotify <- struct{}{}:
			default:
			}
		case capsuleTypeAddressRequest:
			if _, err := parseAddressRequestCapsule(cr); err != nil {
				return err
			}
			return errors.New("connect-ip: address request not yet supported")
		case capsuleTypeRouteAdvertisement:
			capsule, err := parseRouteAdvertisementCapsule(cr)
			if err != nil {
				return err
			}
			c.mu.Lock()
			c.availableRoutes = capsule.IPAddressRanges
			c.mu.Unlock()
			select {
			case c.availableRoutesNotify <- struct{}{}:
			default:
			}
		default:
			return fmt.Errorf("unknown capsule type: %d", t)
		}
	}
}

func (c *Conn) writeToStream() error {
	buf := make([]byte, 0, 1024)
	for {
		select {
		case <-c.closeChan:
			return c.closeErr
		case req, ok := <-c.writes:
			if !ok {
				return nil
			}
			buf = req.capsule.append(buf[:0])
			_, err := c.str.Write(buf)
			req.result <- err
			if err != nil {
				return err
			}
		}
	}
}

func (c *Conn) ReadPacket(b []byte) (int, error) {
	// Fast path: the next expected sequence is already buffered (it arrived early
	// while we were waiting for an earlier one) — deliver it without the network.
	if c.rcvInit {
		if p, ok := c.rcvBuf[c.rcvNextSeq]; ok {
			delete(c.rcvBuf, c.rcvNextSeq)
			c.rcvNextSeq++
			return copy(b, p), nil
		}
	}

	for {
		data, err := c.str.ReceiveDatagram(context.Background())
		if err != nil {
			select {
			case <-c.closeChan:
				return 0, c.closeErr
			default:
				return 0, err
			}
		}
		c.recvObs.observe(data)
		contextID, hlen, err := quicvarint.Parse(data)
		if err != nil {
			// TODO: close connection
			return 0, fmt.Errorf("connect-ip: malformed datagram: %w", err)
		}

		// Legacy unsequenced packets (context ID 0) bypass the reorder buffer.
		if contextID == 0 {
			payload := data[hlen:]
			if err := c.handleIncomingProxiedPacket(payload); err != nil {
				log.Printf("dropping proxied packet: %s", err)
				continue
			}
			return copy(b, payload), nil
		}
		if contextID != contextIDSeqVal {
			continue // unknown context ID — we only proxy IP payloads
		}
		if len(data) < hlen+seqHeaderLen {
			continue // malformed sequenced datagram
		}
		seq := binary.BigEndian.Uint32(data[hlen : hlen+seqHeaderLen])
		payload := data[hlen+seqHeaderLen:]
		if err := c.handleIncomingProxiedPacket(payload); err != nil {
			log.Printf("dropping proxied packet: %s", err)
			continue
		}

		if !c.rcvInit {
			c.rcvInit = true
			c.rcvNextSeq = seq
		}

		// In order: deliver immediately.
		if seq == c.rcvNextSeq {
			c.rcvNextSeq++
			return copy(b, payload), nil
		}
		// Late or duplicate (we already delivered past it): drop.
		if !seqAfter(seq, c.rcvNextSeq) {
			continue
		}
		// Future packet: buffer a copy (the data slice is recycled on the next
		// ReceiveDatagram, so we must own it).
		if _, exists := c.rcvBuf[seq]; !exists {
			cp := make([]byte, len(payload))
			copy(cp, payload)
			c.rcvBuf[seq] = cp
		}
		// Window enforcement: if we're holding too much or this packet is too far
		// ahead, the missing rcvNextSeq is presumed lost (no retransmission in this
		// fork) — skip the gap by delivering the oldest buffered packet.
		if len(c.rcvBuf) > reorderWindow || int32(seq-c.rcvNextSeq) >= reorderWindow {
			if n, ok := c.deliverOldestBuffered(b); ok {
				return n, nil
			}
		}
		// Otherwise keep receiving until rcvNextSeq arrives (then subsequent calls
		// drain any now-consecutive buffered packets via the fast path above).
	}
}

// deliverOldestBuffered abandons the missing c.rcvNextSeq, advances to the oldest
// (nearest-future) buffered sequence, and copies it into b. Used for gap-skip when
// the reorder window is exceeded. Returns false only if the buffer is empty.
func (c *Conn) deliverOldestBuffered(b []byte) (int, bool) {
	var oldest uint32
	bestDist := int32(0)
	found := false
	for k := range c.rcvBuf {
		d := int32(k - c.rcvNextSeq)
		if d <= 0 {
			continue // not a future seq (shouldn't happen; late seqs aren't buffered)
		}
		if !found || d < bestDist {
			found = true
			bestDist = d
			oldest = k
		}
	}
	if !found {
		return 0, false
	}
	p := c.rcvBuf[oldest]
	delete(c.rcvBuf, oldest)
	c.rcvNextSeq = oldest + 1
	return copy(b, p), true
}

func (c *Conn) handleIncomingProxiedPacket(data []byte) error {
	if len(data) == 0 {
		return errors.New("connect-ip: empty packet")
	}
	var src, dst netip.Addr
	var ipProto uint8
	switch v := ipVersion(data); v {
	default:
		return fmt.Errorf("connect-ip: unknown IP versions: %d", v)
	case 4:
		if len(data) < ipv4.HeaderLen {
			return fmt.Errorf("connect-ip: malformed datagram: too short")
		}
		src = netip.AddrFrom4([4]byte(data[12:16]))
		dst = netip.AddrFrom4([4]byte(data[16:20]))
		ipProto = data[9]
	case 6:
		if len(data) < ipv6.HeaderLen {
			return fmt.Errorf("connect-ip: malformed datagram: too short")
		}
		src = netip.AddrFrom16([16]byte(data[8:24]))
		dst = netip.AddrFrom16([16]byte(data[24:40]))
		ipProto = data[6]
	}

	c.mu.Lock()
	assignedAddresses := c.assignedAddresses
	localRoutes := c.localRoutes
	peerAddresses := c.peerAddresses
	c.mu.Unlock()

	// We don't necessarily assign any addresses to the peer.
	// For example, in the Remote Access VPN use case (RFC 9484, section 8.1),
	// the client accepts incoming traffic from all IPs.
	if peerAddresses != nil {
		if !slices.ContainsFunc(peerAddresses, func(p netip.Prefix) bool { return p.Contains(src) }) {
			// TODO: send ICMP
			return fmt.Errorf("connect-ip: datagram source address not allowed: %s", src)
		}
	}

	// The destination IP address is valid if it
	// 1. is within one of the ranges assigned to us, or
	// 2. is within one of the ranges that we advertised to the peer.
	var isAllowedDst bool
	if len(assignedAddresses) > 0 {
		isAllowedDst = slices.ContainsFunc(assignedAddresses, func(p netip.Prefix) bool { return p.Contains(dst) })
	}
	if !isAllowedDst {
		isAllowedDst = slices.ContainsFunc(localRoutes, func(r IPRoute) bool {
			if r.StartIP.Compare(dst) > 0 || dst.Compare(r.EndIP) > 0 {
				return false
			}
			// ICMP is always allowed
			if (ipVersion(data) == 4 && ipProto == ipProtoICMP) || (ipVersion(data) == 6 && ipProto == ipProtoICMPv6) {
				return true
			}
			// TODO: walk the chain of IPv6 extensions
			// See section 4.8 of RFC 9484 for details.
			return r.IPProtocol == 0 || r.IPProtocol == ipProto
		})
	}
	if !isAllowedDst {
		// TODO: send ICMP
		return fmt.Errorf("connect-ip: datagram destination address / protocol not allowed: %s (protocol: %d)", dst, ipProto)
	}
	return nil
}

// WritePacket writes an IP packet to the stream.
// If sending the packet fails, it might return an ICMP packet.
// It is the caller's responsibility to send the ICMP packet to the sender.
func (c *Conn) WritePacket(b []byte) (icmp []byte, err error) {
	data, err := c.composeDatagram(b)
	if err != nil {
		log.Printf("dropping proxied packet (%d bytes) that can't be proxied: %s", len(b), err)
		return nil, nil
	}
	if data == nil {
		return nil, nil
	}
	// SendDatagram copies data into its own frame buffer synchronously, so the
	// composed buffer is dead once SendDatagram returns (including the
	// DatagramTooLargeError path, which returns before copying). Recycle it.
	defer datagramComposeBufPool.Put(data[:0])
	if err := c.str.SendDatagram(data); err != nil {
		var errDTL *quic.DatagramTooLargeError
		if errors.As(err, &errDTL) {
			icmpPacket, err := composeICMPTooLargePacket(b, minMTU)
			if err != nil {
				log.Printf("failed to compose ICMP too large packet: %s", err)
			}
			return icmpPacket, nil
		}
		select {
		case <-c.closeChan:
			return nil, c.closeErr
		default:
			return nil, err
		}
	}
	return nil, nil
}

func (c *Conn) composeDatagram(b []byte) ([]byte, error) {
	// TODO: implement src, dst and ipproto checks
	if len(b) == 0 {
		return nil, nil
	}
	switch v := ipVersion(b); v {
	default:
		return nil, fmt.Errorf("connect-ip: unknown IP versions: %d", v)
	case 4:
		if len(b) < ipv4.HeaderLen {
			return nil, fmt.Errorf("connect-ip: IPv4 packet too short")
		}
		ttl := b[8]
		if ttl <= 1 {
			return nil, fmt.Errorf("connect-ip: datagram TTL too small: %d", ttl)
		}
		b[8]-- // decrement TTL
		// recalculate the checksum
		binary.BigEndian.PutUint16(b[10:12], calculateIPv4Checksum(([ipv4.HeaderLen]byte)(b[:ipv4.HeaderLen])))
	case 6:
		if len(b) < ipv6.HeaderLen {
			return nil, fmt.Errorf("connect-ip: IPv6 packet too short")
		}
		hopLimit := b[7]
		if hopLimit <= 1 {
			return nil, fmt.Errorf("connect-ip: datagram Hop Limit too small: %d", hopLimit)
		}
		b[7]-- // Decrement Hop Limit
	}
	data := datagramComposeBufPool.Get().([]byte)[:0]
	if SequencingEnabled {
		seq := c.sendSeq.Add(1) - 1 // first packet gets seq 0
		data = append(data, contextIDSeq...)
		var s [seqHeaderLen]byte
		binary.BigEndian.PutUint32(s[:], seq)
		data = append(data, s[:]...)
	} else {
		data = append(data, contextIDZero...)
	}
	data = append(data, b...)
	return data, nil
}

// datagramComposeBufPool recycles the per-packet buffer built in composeDatagram.
// Safe because WritePacket is the only caller and SendDatagram copies the buffer
// into its own frame storage before WritePacket recycles it.
var datagramComposeBufPool = sync.Pool{New: func() any { return make([]byte, 0, 1500) }}

func (c *Conn) Close() error {
	c.mu.Lock()
	if c.closeErr == nil {
		c.closeErr = &CloseError{Remote: false}
		close(c.closeChan)
	}
	c.mu.Unlock()
	c.str.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
	err := c.str.Close()
	return err
}

func ipVersion(b []byte) uint8 { return b[0] >> 4 }
