# tunx link protocol

This is the wire format of a link session between two tunxd nodes, version 1.
The implementation is `internal/link`.

A session runs over one reliable, ordered byte stream (`net.Conn`). In
production that is a connection through Xray (VLESS + Reality, TLS, plain
VLESS, SOCKS); in tests it is a pipe or loopback TCP. The dialing side is the
**client**, the accepting side the **server**. After the handshake both sides
are equal: either may open streams.

All integers are big-endian. `str8` is a 1-byte length followed by that many
bytes of UTF-8.

## 1. Handshake

Every handshake message is framed as `len(2) body(len)`, with `len <= 2048`.
The whole handshake must finish within the handshake timeout (default 10 s),
otherwise the connection is closed.

```
client                                          server
  ClientHello  ───────────────────────────────▶
               ◀─────────────────────────────── ServerHello + server signature
  ClientFinish ───────────────────────────────▶
               ◀─────────────────────────────── Accept
  (multiplexed session)
```

### ClientHello

| Field | Size | Contents |
|:--|:--|:--|
| magic | 4 | `TUNX` |
| version | 1 | highest protocol version the client speaks |
| network | str8 | network ID, at most 64 bytes |
| name | str8 | client node name, 1..64 bytes |
| nonce | 32 | fresh random bytes |
| ext_len | 2 | length of extensions, at most 1024 |
| extensions | ext_len | see below; empty in version 1 |

The server closes the connection without a reply when the magic is wrong,
the network ID differs from its own, the name is not in its peer list, or no
common version exists.

### ServerHello

| Field | Size | Contents |
|:--|:--|:--|
| magic | 4 | `TUNX` |
| version | 1 | chosen version: `min(client version, server highest)`; must be at least the server's lowest |
| name | str8 | server node name |
| nonce | 32 | fresh random bytes |
| ext_len | 2 | |
| extensions | ext_len | |
| signature | 64 | ed25519, server key, see below |

The client rejects a version outside the range it speaks and a name that is
not in its peer list, then verifies the signature with that peer's key.

### Transcript and signatures

```
CH = ClientHello body as sent
SH = ServerHello body without the signature
T  = SHA-256("tunx link transcript" || len(CH)(2) || CH || len(SH)(2) || SH)

server signature = Sign(server key, "tunx link server signature" || 0x00 || T)
client signature = Sign(client key, "tunx link client signature" || 0x00 || T)
```

`T` covers both nonces, both names, the network ID, the offered and chosen
versions, and both extension blocks. The two labels differ, so a signature
made in one role is never valid in the other.

### ClientFinish

| Field | Size | Contents |
|:--|:--|:--|
| signature | 64 | client signature over `T` |

The server verifies it with the key it has for the name in ClientHello and
closes the connection on failure.

### Accept

| Field | Size | Contents |
|:--|:--|:--|
| status | 1 | `0` = accepted |

After Accept the connection carries the multiplexer. Nothing else is read or
written by the handshake, so no handshake bytes are buffered past it.

### Extensions

The extension block is a sequence of `type(2) len(2) data(len)` entries.
Unknown types are ignored. Because the blocks are inside `T`, an extension
cannot be stripped or altered without breaking the signatures. Version 1
defines none.

### Version negotiation

A new version is introduced by raising the client's offered version. A server
that speaks it answers with it; an older server answers with its own highest
version, and the client falls back if it still speaks that version. Everything
after the handshake (stream headers, framing, control messages) follows the
chosen version.

## 2. Multiplexer

After Accept both sides run [smux](https://github.com/xtaci/smux) protocol
version 2 (per-stream flow control) on the connection, with smux keepalive
disabled (the control stream does it), a maximum frame size of 32768 bytes,
and by default a 16 MiB session receive buffer and a 1 MiB per-stream buffer.
smux uses odd stream IDs for the client and even for the server, so both may
open streams without coordination.

## 3. Stream header

The opener of a stream writes a header before anything else:

| Field | Size | Contents |
|:--|:--|:--|
| version | 1 | `1` |
| type | 1 | `1` control, `2` flow |
| body_len | 2 | at most 1024 |
| body | body_len | depends on type |

The acceptor reads it within the handshake timeout and closes the stream when
the header is late, malformed, of an unknown version or an unknown type.

### Control stream

Type 1, empty body. The client opens exactly one control stream right after
Accept. The server closes any other control stream, and the client closes any
control stream the server opens.

### Flow header

Type 2. The body encodes `core.FlowMeta`:

| Field | Size | Contents |
|:--|:--|:--|
| proto | 1 | IP protocol number: 6 TCP, 17 UDP, 1 ICMP, 58 ICMPv6 |
| hops | 1 | links crossed so far |
| src | addr | original source |
| dst | addr | destination |
| identity | str8 | authenticated sender, at most 255 bytes |

`addr` is `family(1) address port(2)`: family `4` with 4 address bytes, `6`
with 16, or `0` (no address) with none. An IPv4-mapped IPv6 address stays
family 6. For ICMP the source port is the echo identifier and the destination
port is 0.

Receivers ignore bytes after the known fields, so later versions can append
fields without a new header version.

There is no reply to the header. The acceptor's handler accepts the flow by
using it and refuses it by closing it.

## 4. Flow framing

### TCP (proto 6)

The stream carries chunks in each direction:

```
len(2) data(len)      len = 1..65535 (32766 in practice, one smux frame)
len(2) = 0            end of stream: the sender half-closed
```

- `CloseWrite` sends the zero-length chunk. The peer's reads return EOF; the
  other direction is unaffected.
- `Close` sends the zero-length chunk if it was not sent yet and no write is
  in progress, then closes the smux stream (smux FIN). Data the peer sends
  afterwards is discarded.
- A side that has read the zero-length chunk waits for the smux FIN and then
  closes its stream too, so its own writes fail rather than block on a window
  nobody reads. This mirrors a TCP reset after the peer closed.
- When both zero-length chunks have been exchanged, either side closes the
  smux stream.
- A smux FIN before the zero-length chunk is a reset: reads return
  `ErrFlowReset`.

smux FIN alone cannot carry half-close, because a FIN and a full close look
the same on the wire. The in-band marker separates "no more data from me"
from "I am gone".

### Datagrams (UDP, ICMP, ICMPv6, any other proto)

```
len(2) message(len)   len = 0..65535
```

Each message is written in a single stream write, so concurrent writers never
interleave. Zero-length messages are valid (an empty UDP payload). Messages
larger than 65535 bytes are refused by the sender. A reader with a short
buffer gets a truncated message and the rest is discarded, as with a UDP
socket. ICMP messages start with the type byte; the checksum may be zero and
the receiver recomputes it. `CloseWrite` is a full close; a smux FIN ends the
flow.

## 5. Control messages

On the control stream, in both directions:

| Field | Size | Contents |
|:--|:--|:--|
| type | 1 | message type |
| len | 4 | payload length, at most 1 MiB |
| payload | len | |

| Type | Meaning |
|:--|:--|
| 0x01 | ping; payload is the sender's 8-byte timestamp |
| 0x02 | pong; echoes the ping payload |
| 0x03–0x0F | reserved for the link layer; ignored |
| 0x10–0xFF | application messages (route updates and the like), opaque to the link |

Each side sends a ping every keepalive interval (default 5 s) and answers
every ping with a pong. The timestamp in a pong measures the round-trip time,
smoothed as `srtt = 7/8 srtt + 1/8 sample`. A side that has received no pong
for the keepalive timeout (default 15 s) closes the session. With the
defaults a dead path is detected within about 17 s, which leaves time to
redial inside the 30 s recovery target.

A violation of the control framing closes the session.

## 6. Reconnection

The dialing side redials when a session ends. Attempts back off
exponentially from 250 ms up to 10 s, each wait drawn uniformly from
`[d/2, d]`; a successful handshake resets the backoff.

## 7. Security notes

- **Scope.** The link authenticates the peer node and frames traffic.
  Confidentiality and integrity of the bytes after the handshake are the
  transport's job (Reality or TLS inside Xray). Over a transport without
  them (plain VLESS on an untrusted path, SOCKS), an on-path attacker cannot
  complete a handshake as either node, but can read the session and inject
  or alter data after a handshake between two honest nodes. Use an
  encrypting transport on untrusted paths, or the encryption layer below.
- **Mutual authentication.** Each side proves possession of its ed25519 key
  by signing the transcript. Keys are configured per peer; a name not in the
  peer list is refused.
- **Replay.** Each side contributes a fresh 32-byte nonce, and each signature
  covers both. A recorded ClientFinish or ServerHello fails against any new
  handshake.
- **Splicing and tampering.** The signatures cover the whole transcript, so an
  attacker cannot combine messages from two handshakes, change a name, the
  network ID, a nonce, a version or an extension, or downgrade the version
  without the signature check failing.
- **Reflection.** Server and client signatures use different labels.
- **Identity disclosure.** The ClientHello carries the client name in the
  clear and the server signs a hello for any client whose name and network
  are known, before the client has proven anything. The transport hides
  this from observers, and Xray admits only its own users.
- **Resource limits.** Handshake messages are capped at 2048 bytes, stream
  headers at 1024, control messages at 1 MiB, datagrams at 65535. Handshake
  and stream headers have deadlines. Flows the peer opens wait until the
  local side serves them; the smux buffers bound their memory.
- **Flow identity.** `FlowMeta.Identity` is a claim made by the peer. The
  receiving node decides whether this peer may carry that identity (see the
  policy section of `design.md`).

### Extension point: encryption layer

A later version can add authenticated encryption below the multiplexer
without changing anything above it:

1. Each side sends an ephemeral X25519 public key as a handshake extension.
   Both extension blocks are inside `T`, so the existing signatures
   authenticate the key exchange (a SIGMA-style signed Diffie-Hellman).
2. Both derive keys with HKDF-SHA256 from the shared secret, salted with
   `T`, one key per direction.
3. After Accept, the connection carries AEAD records,
   `len(2) ciphertext(len)` with a per-direction counter nonce, and the
   multiplexer runs on the decrypted stream.

A node signals support by offering the extension; the layer is used only
when both hellos carry it. A node that requires it refuses a peer whose hello
lacks it, and the requirement must be configured per link so a downgrade by
stripping the extension is impossible (stripping would also break the
signatures).
