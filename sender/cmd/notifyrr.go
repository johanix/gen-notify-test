package cmd

import (
        "encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"

	"github.com/miekg/dns"
)

const (
      TypeAPAIR = 0x0F99
      TypeNOTIFY = 0x0F9A
)

type APAIR struct {
	addr [2]net.IP
}

type NOTIFY struct {
     Type   uint16
     Scheme uint8
     Port   uint16
     Dest   string
}

func NewAPAIR() dns.PrivateRdata { return new(APAIR) }

func NewNOTIFY() dns.PrivateRdata { return new(NOTIFY) }

func (rd *APAIR) String() string { return rd.addr[0].String() + " " + rd.addr[1].String() }

func (rd *NOTIFY) StringOLD() string { return dns.TypeToString[rd.Type] + " " + string(rd.Scheme) + " " + string(rd.Port) + " " + rd.Dest }

func (rd *NOTIFY) String() string {
     return fmt.Sprintf("%s %d %d %s", dns.TypeToString[rd.Type], rd.Scheme, rd.Port, rd.Dest)
}

func (rd *APAIR) Parse(txt []string) error {
	if len(txt) != 2 {
		return errors.New("two addresses required for APAIR")
	}
	for i, s := range txt {
		ip := net.ParseIP(s)
		if ip == nil {
			return errors.New("invalid IP in APAIR text representation")
		}
		rd.addr[i] = ip
	}
	return nil
}

func (rd *NOTIFY) Parse(txt []string) error {
	if len(txt) != 4 {
		return errors.New("NOTIFY requires a type, a scheme, a port and a destination")
	}
	t := dns.StringToType[txt[0]]
	if t == 0 {
		return errors.New("invalid type in NOTIFY specification")
	}

	scheme, err := strconv.Atoi(txt[1])
	if err != nil {
		return fmt.Errorf("invalid NOTIFY scheme: %s. Error: %v", txt[1], err)
	}
	
	port, err := strconv.Atoi(txt[2])
	if err != nil {
		return fmt.Errorf("invalid NOTIFY port: %s. Error: %v", txt[2], err)
	}

	dst := dns.Fqdn(txt[3])
	if _, ok := dns.IsDomainName(dst); !ok {
		return fmt.Errorf("invalid NOTIFY destination: %s. Error: %v", txt[3], err)
	}

	rd.Type = t
	rd.Scheme = uint8(scheme)
	rd.Port = uint16(port)
	rd.Dest = dst

	return nil
}

func unpackUint8(msg []byte, off int) (i uint8, off1 int, err error) {
	if off+1 > len(msg) {
		return 0, len(msg), errors.New("overflow unpacking uint8")
	}
	return msg[off], off + 1, nil
}

func packUint8(i uint8, msg []byte, off int) (off1 int, err error) {
	if off+1 > len(msg) {
		return len(msg), errors.New("overflow packing uint8")
	}
	msg[off] = i
	return off + 1, nil
}

func unpackUint16(msg []byte, off int) (i uint16, off1 int, err error) {
	if off+2 > len(msg) {
		return 0, len(msg), errors.New("overflow unpacking uint16")
	}
	return binary.BigEndian.Uint16(msg[off:]), off + 2, nil
}

func packUint16 (i uint16, msg []byte, off int) (off1 int, err error) {
	if off+2 > len(msg) {
		return len(msg), errors.New("overflow packing uint16")
	}
	binary.BigEndian.PutUint16(msg[off:], i)
	return off + 2, nil
}

func (rd *APAIR) Pack(buf []byte) (int, error) {
	b := append([]byte(rd.addr[0]), []byte(rd.addr[1])...)
	n := copy(buf, b)
	if n != len(b) {
		return n, dns.ErrBuf
	}
	return n, nil
}

func (rd *NOTIFY) Pack(buf []byte) (int, error) {
        var off int
        off, err := packUint16(rd.Type, buf, off)
	if err != nil {
	   return off, err
	}

	off, err = packUint8(rd.Scheme, buf, off)
	if err != nil {
	   return off, err
	}

	off, err = packUint16(rd.Port, buf, off)
	if err != nil {
	   return off, err
	}

	off, err = dns.PackDomainName(rd.Dest, buf, 0, nil, false)
	if err != nil {
	   return off, err
	}
	
	return off, nil
}

func (rd *APAIR) Unpack(buf []byte) (int, error) {
	ln := net.IPv4len * 2
	if len(buf) != ln {
		return 0, errors.New("invalid length of APAIR rdata")
	}
	cp := make([]byte, ln)
	copy(cp, buf)

	rd.addr[0] = net.IP(cp[:3])
	rd.addr[1] = net.IP(cp[4:])

	return len(buf), nil
}

func (rd *NOTIFY) Unpack(buf []byte) (int, error) {
//	rdStart := off
//	_ = rdStart
	var off = 0
	var err error

	rd.Type, off, err = unpackUint16(buf, off)
	if err != nil {
		return off, err
	}
	if off == len(buf) {
		return off, nil
	}
	rd.Scheme, off, err = unpackUint8(buf, off)
	if err != nil {
		return off, err
	}
	if off == len(buf) {
		return off, nil
	}
	rd.Port, off, err = unpackUint16(buf, off)
	if err != nil {
		return off, err
	}
	if off == len(buf) {
		return off, nil
	}
	rd.Dest, off, err = dns.UnpackDomainName(buf, off)
	if err != nil {
		return off, err
	}
	return off, nil
}

func (rd *APAIR) Copy(dest dns.PrivateRdata) error {
	cp := make([]byte, rd.Len())
	_, err := rd.Pack(cp)
	if err != nil {
		return err
	}

	d := dest.(*APAIR)
	d.addr[0] = net.IP(cp[:3])
	d.addr[1] = net.IP(cp[4:])
	return nil
}

func (rd *NOTIFY) Copy(dest dns.PrivateRdata) error {
	cp := make([]byte, rd.Len())
	_, err := rd.Pack(cp)
	if err != nil {
		return err
	}

	d := dest.(*NOTIFY)
	d.Type = rd.Type
	d.Scheme = rd.Scheme
	d.Port = rd.Port
	d.Dest = rd.Dest
	return nil
}

func (rd *NOTIFY) Header() *dns.RR_Header {
     var hdr = dns.RR_Header{}
     return &hdr
}

func (rd *APAIR) Len() int {
	return net.IPv4len * 2
}

func (rd *NOTIFY) Len() int {
	return 1 + 2 + 2 + len(rd.Dest)
}

func xmain() {
	dns.PrivateHandle("APAIR", TypeAPAIR, NewAPAIR)
	defer dns.PrivateHandleRemove(TypeAPAIR)
	var oldId = dns.Id
	dns.Id = func() uint16 { return 3 }
	defer func() { dns.Id = oldId }()

	rr, err := dns.NewRR("miek.nl. APAIR (1.2.3.4    1.2.3.5)")
	if err != nil {
		log.Fatal("could not parse APAIR record: ", err)
	}
	fmt.Println(rr) // see first line of Output below

	m := new(dns.Msg)
	m.SetQuestion("miek.nl.", TypeAPAIR)
	m.Answer = append(m.Answer, rr)

	fmt.Println(m)
}

func RegisterNotifyRR() error {
	dns.PrivateHandle("NOTIFY", TypeNOTIFY, NewNOTIFY)
	// defer dns.PrivateHandleRemove(TypeNOTIFY)
	// var oldId = dns.Id
	// dns.Id = func() uint16 { return 3 }
	// defer func() {
	//      dns.Id = oldId
	// }()
	return nil
}

func GenerateNotifyRR(t string, scheme uint8, port uint16, dest string) {
	// dns.PrivateHandle("NOTIFY", TypeNOTIFY, NewNOTIFY)
	// defer dns.PrivateHandleRemove(TypeNOTIFY)
	// var oldId = dns.Id
	// dns.Id = func() uint16 { return 3 }
	// defer func() {
	//      dns.Id = oldId
	// }()

	rr, err := dns.NewRR("axfr.net. NOTIFY CDS 1 5302 notifications.axfr.net.")
	if err != nil {
		log.Fatal("could not parse NOTIFY record: ", err)
	}
	fmt.Printf("NOTIFY RR: %s\n", rr.String()) // see first line of Output below
	hdr := rr.Header()
	fmt.Printf("Header: %s\n", hdr.String())
	u := new(dns.RFC3597)
	u.ToRFC3597(rr)
	fmt.Printf("RFC 3597 format: \"%s\"\n", u.String())

	m := new(dns.Msg)
	m.SetQuestion("axfr.net.", TypeNOTIFY)
	m.Answer = append(m.Answer, rr)

	fmt.Println(m)
}
