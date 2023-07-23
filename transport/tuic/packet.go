package tuic

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"os"
	"sync"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/atomic"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

var udpMessagePool = sync.Pool{
	New: func() interface{} {
		return new(udpMessage)
	},
}

func releaseMessages(messages []*udpMessage) {
	for _, message := range messages {
		if message != nil {
			*message = udpMessage{}
			udpMessagePool.Put(message)
		}
	}
}

type udpMessage struct {
	sessionID     uint16
	packetID      uint16
	fragmentTotal uint8
	fragmentID    uint8
	destination   M.Socksaddr
	dataLength    uint16
	data          *buf.Buffer
}

func (m *udpMessage) release() {
	*m = udpMessage{}
	udpMessagePool.Put(m)
}

func (m *udpMessage) releaseMessage() {
	m.data.Release()
	m.release()
}

func (m *udpMessage) pack() *buf.Buffer {
	buffer := buf.NewSize(m.headerSize() + m.data.Len())
	common.Must(
		buffer.WriteByte(Version),
		buffer.WriteByte(CommandPacket),
		binary.Write(buffer, binary.BigEndian, m.sessionID),
		binary.Write(buffer, binary.BigEndian, m.packetID),
		binary.Write(buffer, binary.BigEndian, m.fragmentTotal),
		binary.Write(buffer, binary.BigEndian, m.fragmentID),
		binary.Write(buffer, binary.BigEndian, uint16(m.data.Len())),
		addressSerializer.WriteAddrPort(buffer, m.destination),
		common.Error(buffer.Write(m.data.Bytes())),
	)
	return buffer
}

func (m *udpMessage) headerSize() int {
	return 2 + 10 + addressSerializer.AddrPortLen(m.destination)
}

func fragUDPMessage(message *udpMessage, maxPacketSize int) []*udpMessage {
	if message.data.Len() <= maxPacketSize {
		return []*udpMessage{message}
	}
	var fragments []*udpMessage
	originPacket := message.data.Bytes()
	udpMTU := maxPacketSize - message.headerSize()
	for remaining := len(originPacket); remaining > 0; remaining -= udpMTU {
		fragment := udpMessagePool.Get().(*udpMessage)
		*fragment = *message
		if remaining > udpMTU {
			fragment.data = buf.As(originPacket[:udpMTU])
			originPacket = originPacket[udpMTU:]
		} else {
			fragment.data = buf.As(originPacket)
			originPacket = nil
		}
		fragments = append(fragments, fragment)
	}
	fragmentTotal := uint16(len(fragments))
	for index, fragment := range fragments {
		fragment.fragmentID = uint8(index)
		fragment.fragmentTotal = uint8(fragmentTotal)
		if index > 0 {
			fragment.destination = M.Socksaddr{}
		}
	}
	return fragments
}

type udpPacketConn struct {
	ctx       context.Context
	cancel    common.ContextCancelCauseFunc
	connId    uint16
	quicConn  quic.Connection
	data      chan *udpMessage
	udpStream bool
	udpMTU    int
	packetId  atomic.Uint32
	closeOnce sync.Once
	isServer  bool
}

func (c *udpPacketConn) ReadPacketThreadSafe() (buffer *buf.Buffer, destination M.Socksaddr, err error) {
	select {
	case p := <-c.data:
		buffer = p.data
		destination = p.destination
		p.release()
		return
	case <-c.ctx.Done():
		return nil, M.Socksaddr{}, io.ErrClosedPipe
	}
}

func (c *udpPacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	select {
	case p := <-c.data:
		_, err = buffer.ReadOnceFrom(p.data)
		destination = p.destination
		p.releaseMessage()
		return
	case <-c.ctx.Done():
		return M.Socksaddr{}, io.ErrClosedPipe
	}
}

func (c *udpPacketConn) WaitReadPacket(newBuffer func() *buf.Buffer) (destination M.Socksaddr, err error) {
	select {
	case p := <-c.data:
		_, err = newBuffer().ReadOnceFrom(p.data)
		destination = p.destination
		p.releaseMessage()
		return
	case <-c.ctx.Done():
		return M.Socksaddr{}, io.ErrClosedPipe
	}
}

func (c *udpPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	select {
	case pkt := <-c.data:
		n = copy(p, pkt.data.Bytes())
		addr = pkt.destination.UDPAddr()
		pkt.releaseMessage()
		return n, addr, nil
	case <-c.ctx.Done():
		return 0, nil, io.ErrClosedPipe
	}
}

func (c *udpPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	select {
	case <-c.ctx.Done():
		return net.ErrClosed
	default:
	}
	if buffer.Len() > 0xffff {
		return quic.ErrMessageTooLarge(0xffff)
	}
	packetId := c.packetId.Add(1)
	if packetId > math.MaxUint16 {
		c.packetId.Store(0)
		packetId = 0
	}
	message := udpMessagePool.Get().(*udpMessage)
	*message = udpMessage{
		sessionID:     c.connId,
		packetID:      uint16(packetId),
		fragmentTotal: 1,
		destination:   destination,
		data:          buffer,
	}
	defer message.releaseMessage()
	var err error
	if c.udpMTU > 0 && buffer.Len() > c.udpMTU {
		err = c.writePackets(fragUDPMessage(message, c.udpMTU))
	} else {
		err = c.writePacket(message)
	}
	if err == nil {
		return nil
	}
	var tooLargeErr quic.ErrMessageTooLarge
	if !errors.As(err, &tooLargeErr) {
		return err
	}
	c.udpMTU = int(tooLargeErr)
	return c.writePackets(fragUDPMessage(message, c.udpMTU))
}

func (c *udpPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	select {
	case <-c.ctx.Done():
		return 0, net.ErrClosed
	default:
	}
	if len(p) > 0xffff {
		return 0, quic.ErrMessageTooLarge(0xffff)
	}
	packetId := c.packetId.Add(1)
	if packetId > math.MaxUint16 {
		c.packetId.Store(0)
		packetId = 0
	}
	message := udpMessagePool.Get().(*udpMessage)
	*message = udpMessage{
		sessionID:     c.connId,
		packetID:      uint16(packetId),
		fragmentTotal: 1,
		destination:   M.SocksaddrFromNet(addr),
		data:          buf.As(p),
	}
	if c.udpMTU > 0 && len(p) > c.udpMTU {
		err = c.writePackets(fragUDPMessage(message, c.udpMTU))
		if err == nil {
			return len(p), nil
		}
	} else {
		err = c.writePacket(message)
	}
	if err == nil {
		return len(p), nil
	}
	var tooLargeErr quic.ErrMessageTooLarge
	if !errors.As(err, &tooLargeErr) {
		return
	}
	c.udpMTU = int(tooLargeErr)
	err = c.writePackets(fragUDPMessage(message, c.udpMTU))
	if err == nil {
		return len(p), nil
	}
	return
}

func (c *udpPacketConn) writePackets(messages []*udpMessage) error {
	defer releaseMessages(messages)
	for _, message := range messages {
		err := c.writePacket(message)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *udpPacketConn) writePacket(message *udpMessage) error {
	if !c.udpStream {
		buffer := message.pack()
		err := c.quicConn.SendMessage(buffer.Bytes())
		buffer.Release()
		if err != nil {
			return err
		}
	} else {
		stream, err := c.quicConn.OpenUniStream()
		if err != nil {
			return err
		}
		buffer := message.pack()
		_, err = stream.Write(buffer.Bytes())
		buffer.Release()
		stream.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *udpPacketConn) Close() error {
	c.closeOnce.Do(func() {
		c.closeWithError(os.ErrClosed)
	})
	return nil
}

func (c *udpPacketConn) closeWithError(err error) {
	c.cancel(err)
	if !c.isServer {
		buffer := buf.NewSize(4)
		defer buffer.Release()
		buffer.WriteByte(Version)
		buffer.WriteByte(CommandDissociate)
		binary.Write(buffer, binary.BigEndian, c.connId)
		sendStream, openErr := c.quicConn.OpenUniStream()
		if openErr != nil {
			return
		}
		defer sendStream.Close()
		sendStream.Write(buffer.Bytes())
	}
}

func (c *udpPacketConn) LocalAddr() net.Addr {
	return c.quicConn.LocalAddr()
}

func (c *udpPacketConn) SetDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *udpPacketConn) SetReadDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *udpPacketConn) SetWriteDeadline(t time.Time) error {
	return os.ErrInvalid
}

type defragger struct {
	packetId uint16
	messages []*udpMessage
	count    uint8
}

func (d *defragger) feed(m *udpMessage) *udpMessage {
	if m.fragmentTotal <= 1 {
		return m
	}
	if m.fragmentID >= m.fragmentTotal {
		return nil
	}
	if m.packetID != d.packetId {
		releaseMessages(d.messages)
		d.packetId = m.packetID
		d.messages = make([]*udpMessage, m.fragmentTotal)
		d.count = 1
		d.messages[m.fragmentID] = m
	} else if d.messages[m.fragmentID] == nil {
		d.messages[m.fragmentID] = m
		d.count++
		if int(d.count) == len(d.messages) {
			newMessage := udpMessagePool.Get().(*udpMessage)
			*newMessage = *d.messages[0]
			newMessage.data = buf.NewSize(int(m.dataLength))
			for _, message := range d.messages {
				newMessage.data.Write(message.data.Bytes())
				message.releaseMessage()
			}
			d.messages = nil
			return newMessage
		}
	}
	return nil
}

func decodeUDPMessage(message *udpMessage, reader io.Reader) error {
	err := binary.Read(reader, binary.BigEndian, &message.sessionID)
	if err != nil {
		return err
	}
	err = binary.Read(reader, binary.BigEndian, &message.packetID)
	if err != nil {
		return err
	}
	err = binary.Read(reader, binary.BigEndian, &message.fragmentTotal)
	if err != nil {
		return err
	}
	err = binary.Read(reader, binary.BigEndian, &message.fragmentID)
	if err != nil {
		return err
	}
	err = binary.Read(reader, binary.BigEndian, &message.dataLength)
	if err != nil {
		return err
	}
	message.destination, err = addressSerializer.ReadAddrPort(reader)
	if err != nil {
		return err
	}
	message.data = buf.NewSize(int(message.dataLength))
	_, err = message.data.ReadFullFrom(reader, message.data.FreeLen())
	if err != nil {
		return err
	}
	return nil
}
