package tray

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"runtime"
)

// iconBytes returns a small filled-circle indicator in the format the current
// platform's system tray expects: PNG on macOS/Linux, ICO (PNG-in-ICO) on
// Windows. color is "green" or "red".
func iconBytes(c string) []byte {
	col := color.RGBA{0xff, 0x41, 0x36, 0xff} // red
	if c == "green" {
		col = color.RGBA{0x2e, 0xcc, 0x40, 0xff}
	}
	p := circlePNG(col)
	if runtime.GOOS == "windows" {
		return icoWrap(p)
	}
	return p
}

func circlePNG(c color.Color) []byte {
	const n = 22
	img := image.NewRGBA(image.Rect(0, 0, n, n))
	cx, cy, r := float64(n)/2, float64(n)/2, float64(n)/2-1
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			dx, dy := float64(x)+0.5-cx, float64(y)+0.5-cy
			if dx*dx+dy*dy <= r*r {
				img.Set(x, y, c)
			}
		}
	}
	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return buf.Bytes()
}

// icoWrap packages a PNG into a single-image .ico (Windows Vista+ accepts PNG
// payloads inside ICO).
func icoWrap(pngBytes []byte) []byte {
	var b bytes.Buffer
	// ICONDIR
	_ = binary.Write(&b, binary.LittleEndian, uint16(0)) // reserved
	_ = binary.Write(&b, binary.LittleEndian, uint16(1)) // type: icon
	_ = binary.Write(&b, binary.LittleEndian, uint16(1)) // image count
	// ICONDIRENTRY
	b.WriteByte(22)                                                  // width
	b.WriteByte(22)                                                  // height
	b.WriteByte(0)                                                   // palette colors
	b.WriteByte(0)                                                   // reserved
	_ = binary.Write(&b, binary.LittleEndian, uint16(1))             // color planes
	_ = binary.Write(&b, binary.LittleEndian, uint16(32))            // bits per pixel
	_ = binary.Write(&b, binary.LittleEndian, uint32(len(pngBytes))) // image size
	_ = binary.Write(&b, binary.LittleEndian, uint32(6+16))          // offset to image
	b.Write(pngBytes)
	return b.Bytes()
}
