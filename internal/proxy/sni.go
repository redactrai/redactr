package proxy

import (
	"encoding/binary"
	"errors"
)

// errNoSNI signals that the ClientHello was syntactically OK but didn't
// carry a server_name extension.
var errNoSNI = errors.New("client hello has no SNI extension")

// parseSNI extracts the server_name from a TLS ClientHello in `data`.
// Returns errNoSNI if the hello is well-formed but lacks SNI; returns
// other errors for malformed input.
//
// Reference: RFC 5246 §7.4.1.2 (ClientHello), RFC 6066 §3 (SNI).
func parseSNI(data []byte) (string, error) {
	// TLS record header: type(1) + version(2) + length(2) = 5 bytes.
	if len(data) < 5 {
		return "", errors.New("tls: short record header")
	}
	if data[0] != 0x16 {
		return "", errors.New("tls: not a handshake record")
	}
	recLen := int(binary.BigEndian.Uint16(data[3:5]))
	if len(data) < 5+recLen {
		return "", errors.New("tls: record truncated")
	}
	hs := data[5 : 5+recLen]
	// Handshake header: type(1) + length(3).
	if len(hs) < 4 {
		return "", errors.New("tls: short handshake")
	}
	if hs[0] != 0x01 {
		return "", errors.New("tls: not a ClientHello")
	}
	hsLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if len(hs) < 4+hsLen {
		return "", errors.New("tls: handshake truncated")
	}
	body := hs[4 : 4+hsLen]
	// Body: version(2) + random(32) + session_id_length(1) + session_id +
	//       cipher_suites_length(2) + cipher_suites +
	//       compression_methods_length(1) + compression_methods +
	//       extensions_length(2) + extensions
	if len(body) < 2+32+1 {
		return "", errors.New("tls: hello too short")
	}
	p := 2 + 32
	sidLen := int(body[p])
	p++
	if len(body) < p+sidLen {
		return "", errors.New("tls: bad session id")
	}
	p += sidLen
	if len(body) < p+2 {
		return "", errors.New("tls: missing cipher suites length")
	}
	csLen := int(binary.BigEndian.Uint16(body[p:]))
	p += 2
	if len(body) < p+csLen {
		return "", errors.New("tls: bad cipher suites")
	}
	p += csLen
	if len(body) < p+1 {
		return "", errors.New("tls: missing compression methods length")
	}
	cmLen := int(body[p])
	p++
	if len(body) < p+cmLen {
		return "", errors.New("tls: bad compression methods")
	}
	p += cmLen
	if len(body) < p+2 {
		return "", errors.New("tls: missing extensions length")
	}
	extLen := int(binary.BigEndian.Uint16(body[p:]))
	p += 2
	if len(body) < p+extLen {
		return "", errors.New("tls: extensions truncated")
	}
	exts := body[p : p+extLen]
	for len(exts) >= 4 {
		extType := binary.BigEndian.Uint16(exts[0:2])
		extDataLen := int(binary.BigEndian.Uint16(exts[2:4]))
		if len(exts) < 4+extDataLen {
			return "", errors.New("tls: extension truncated")
		}
		extData := exts[4 : 4+extDataLen]
		if extType == 0 {
			// SNI extension: list_length(2), then entries:
			//   name_type(1) + name_length(2) + name
			if len(extData) < 2 {
				return "", errors.New("tls: short SNI list")
			}
			listLen := int(binary.BigEndian.Uint16(extData[0:2]))
			if len(extData) < 2+listLen {
				return "", errors.New("tls: SNI list truncated")
			}
			list := extData[2 : 2+listLen]
			for len(list) >= 3 {
				nameType := list[0]
				nameLen := int(binary.BigEndian.Uint16(list[1:3]))
				if len(list) < 3+nameLen {
					return "", errors.New("tls: SNI name truncated")
				}
				if nameType == 0 {
					return string(list[3 : 3+nameLen]), nil
				}
				list = list[3+nameLen:]
			}
			return "", errNoSNI
		}
		exts = exts[4+extDataLen:]
	}
	return "", errNoSNI
}
