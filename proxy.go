package connectip

import (
	"net/http"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

var contextIDZero = quicvarint.Append([]byte{}, 0)

// contextIDSeq (HTTP Datagram Context ID 1) marks a "sequenced IP packet":
// the framing is [contextID=1][4-byte big-endian seq][IP packet]. This is a
// private extension used by the bonded tmasque tunnels to carry a per-connection
// monotonic sequence so the receiver can restore order (see Conn.sendSeq and the
// receive reorder buffer). Context ID 0 (plain IP, no seq) remains supported.
var contextIDSeq = quicvarint.Append([]byte{}, 1)

// contextIDSeqVal is the numeric form of contextIDSeq, for comparing the parsed
// context ID on the receive path.
const contextIDSeqVal uint64 = 1

// seqHeaderLen is the byte length of the sequence number that follows the
// contextIDSeq varint in a sequenced datagram.
const seqHeaderLen = 4

// SequencingEnabled controls whether WritePacket stamps the contextIDSeq header.
// Both peers must run a build that understands context ID 1; a peer on the old
// framing drops context-1 datagrams (no corruption, but total loss), so deploy
// both sides together. Defaults on for the tmasque tunnels.
var SequencingEnabled = false

type Proxy struct{}

func (s *Proxy) Proxy(w http.ResponseWriter, _ *Request) (*Conn, error) {
	w.Header().Set(http3.CapsuleProtocolHeader, capsuleProtocolHeaderValue)
	w.WriteHeader(http.StatusOK)

	str := w.(http3.HTTPStreamer).HTTPStream()
	return newProxiedConn(str), nil
}
