package tray

import (
	"bytes"
	"testing"
)

func TestIconBytesNonEmpty(t *testing.T) {
	for _, c := range []string{"green", "red"} {
		if b := iconBytes(c); len(b) == 0 {
			t.Errorf("iconBytes(%q) returned no bytes", c)
		}
	}
}

func TestIcoWrapStructure(t *testing.T) {
	png := []byte{0x89, 'P', 'N', 'G', 1, 2, 3, 4, 5}
	ico := icoWrap(png)

	if len(ico) != 6+16+len(png) {
		t.Fatalf("ico length = %d, want %d", len(ico), 6+16+len(png))
	}
	// ICONDIR: reserved=0, type=1, count=1 (little-endian uint16s)
	if ico[0] != 0 || ico[1] != 0 || ico[2] != 1 || ico[3] != 0 || ico[4] != 1 || ico[5] != 0 {
		t.Errorf("bad ICONDIR header: % x", ico[:6])
	}
	// ICONDIRENTRY bytesInRes (bytes 14..18) == len(png)
	size := uint32(ico[14]) | uint32(ico[15])<<8 | uint32(ico[16])<<16 | uint32(ico[17])<<24
	if int(size) != len(png) {
		t.Errorf("bytesInRes = %d, want %d", size, len(png))
	}
	// ICONDIRENTRY offset (bytes 18..22) == 22
	off := uint32(ico[18]) | uint32(ico[19])<<8 | uint32(ico[20])<<16 | uint32(ico[21])<<24
	if off != 22 {
		t.Errorf("image offset = %d, want 22", off)
	}
	// payload at offset 22 is the original PNG
	if !bytes.Equal(ico[22:], png) {
		t.Errorf("payload mismatch")
	}
}
