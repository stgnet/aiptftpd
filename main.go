// white router recovery (fixed ip tftp handler)

package main

import (
	"bytes"
	"encoding/binary"
	// "encoding/hex"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func ztString(bytes []byte) string {
	for i, b := range bytes {
		if b == 0 {
			return string(bytes[:i])
		}
	}
	return ""
}

func terr(msg string) []byte {
	fmt.Printf("ERROR: %s\n", msg)
	var b bytes.Buffer
	b.Grow(len(msg) + 5)
	b.Write([]byte{0, 5, 0, 0})
	b.Write([]byte(msg))
	b.Write([]byte{0})
	return b.Bytes()
}

var filedata []byte

func open(filename string) bool {
	var err error
	filedata, err = ioutil.ReadFile(filename)
	if err != nil {
		fmt.Printf("Error reading file %s: %v\n", filename, err)
		return false
	}
	fmt.Printf("Loaded %d bytes from file %s\n", len(filedata), filename)
	return true
}

func data(number uint16) []byte {
	var b bytes.Buffer

	start := int(number) * 512
	if start > len(filedata) {
		// ignore the request, i.e. respond with zero bytes
		fmt.Print("end\n")
		//return terr("requested block beyond file")
		return b.Bytes()
	}
	end := start + 512
	if end > len(filedata) {
		end = len(filedata)
	}
	chunk := filedata[start:end]
	number += 1
	b.Grow(len(chunk) + 4)
	b.Write([]byte{0, 3})
	b.Write([]byte{
		byte((number >> 8) & 0xff),
		byte((number) & 0xff),
	})
	b.Write(chunk)
	// fmt.Printf("Sending block # %d\n", number)
	fmt.Printf(".")
	return b.Bytes()
}

func rrq(rq []byte) []byte {
	filename := ztString(rq[2:])
	fmt.Printf("RRQ: %s\n", filename)
	if len(os.Args) >= 2 {
		fmt.Printf("Using instead supplied file %s\n", filename)
		filename = os.Args[1]
	}
	if !open(filename) {
		return terr("file not found")
	}
	return data(0)
}

func ack(rq []byte) []byte {
	return data(binary.BigEndian.Uint16(rq[2:4]))
}

func tftp(payload []byte) []byte {
	// fmt.Printf("TFTP: %s\n", hex.EncodeToString(payload))
	if payload[0] != 0 {
		return terr("bad opcode")
	}
	switch payload[1] {
	case 1: // RRQ
		return rrq(payload)
	case 4: // ACK
		return ack(payload)
	default:
		return terr("invalid opcode")
	}
}

func sendUDP(handle *pcap.Handle, iface *net.Interface, dstMAC net.HardwareAddr, srcIP net.IP, dstIP net.IP, srcPort layers.UDPPort, dstPort layers.UDPPort, payload []byte) {
	if len(payload) == 0 {
		return
	}
	eth := layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Protocol: layers.IPProtocolUDP,
	}
	udp := layers.UDP{
		SrcPort: srcPort,
		DstPort: dstPort,
	}
	udp.SetNetworkLayerForChecksum(&ip)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	sErr := gopacket.SerializeLayers(buf, opts, &eth, &ip, &udp, gopacket.Payload(payload))
	if sErr != nil {
		fmt.Printf("Unable to construct packet: %v\n", sErr)
		return
	}
	// fmt.Printf("SEND: %s\n", hex.EncodeToString(buf.Bytes()))
	wErr := handle.WritePacketData(buf.Bytes())
	if wErr != nil {
		fmt.Printf("Failed to write packet: %v\n", wErr)
		return
	}
}

func sendArp(handle *pcap.Handle, iface *net.Interface, srcIP net.IP, dstMAC net.HardwareAddr, dstIP net.IP) {
	eth := layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPReply,
		SourceHwAddress:   []byte(iface.HardwareAddr),
		SourceProtAddress: []byte(srcIP),
		DstHwAddress:      []byte(dstMAC),
		DstProtAddress:    []byte(dstIP),
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	sErr := gopacket.SerializeLayers(buf, opts, &eth, &arp)
	if sErr != nil {
		fmt.Printf("Unable to construct arp packet: %v\n", sErr)
		return
	}
	wErr := handle.WritePacketData(buf.Bytes())
	if wErr != nil {
		fmt.Printf("Failed to write packet: %v\n", wErr)
		return
	}
}

func monitor(iface net.Interface) {
	handle, h_err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	if h_err != nil {
		fmt.Printf("Unable to open %s: %v\n", iface.Name, h_err)
		return
	}

	bpfErr := handle.SetBPFFilter("arp or port 69")
	if bpfErr != nil {
		fmt.Printf("Unable to filter %s: %v\n", iface.Name, bpfErr)
		return
	}

	fmt.Printf("Monitoring interface %s\n", iface.Name)
	pkts := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet).Packets()
	for {
		var packet gopacket.Packet
		select {
		case packet = <-pkts:
			ethLayer := packet.Layer(layers.LayerTypeEthernet)
			if ethLayer == nil {
				fmt.Printf("%s: Received non-ethernet packet?", iface.Name)
				continue
			}
			eth := ethLayer.(*layers.Ethernet)
			if eth.SrcMAC.String() == iface.HardwareAddr.String() {
				continue
			}
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer != nil {
				arp := arpLayer.(*layers.ARP)
				srcIP := net.IP(arp.SourceProtAddress).To4()
				dstIP := net.IP(arp.DstProtAddress).To4()
				dstMAC := net.HardwareAddr(arp.DstHwAddress)
				if srcIP.String() != "192.168.1.119" {
					continue
				}
				if dstIP.String() != "192.168.1.88" {
					continue
				}
				fmt.Printf("%s: ARP %d %v => %v\n",
					iface.Name,
					arp.Operation,
					srcIP,
					dstIP,
				)
				fmt.Printf("Sending arp reply\n")
				sendArp(handle, &iface, dstIP, dstMAC, srcIP)
				continue
			}
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			if ipLayer == nil {
				fmt.Printf("%s: Received non-ip packet?", iface.Name)
				continue
			}
			ip := ipLayer.(*layers.IPv4)
			udpLayer := packet.Layer(layers.LayerTypeUDP)
			if udpLayer != nil {
				udp := udpLayer.(*layers.UDP)
				if udp.DstPort != 69 {
					fmt.Printf("%s: UDP %d => %d with %d bytes\n", iface.Name, udp.SrcPort, udp.DstPort, udp.Length)
					continue
				}
				response := tftp(udp.Payload)
				sendUDP(handle, &iface, eth.SrcMAC,
					ip.DstIP, ip.SrcIP,
					udp.DstPort, udp.SrcPort,
					response)

				continue
			}
			fmt.Printf("Unknown packet: %#v\n", eth)
		}
	}
}

func main() {
	ifaces, ifErr := net.Interfaces()
	if ifErr != nil {
		panic(ifErr)
	}
	for _, iface := range ifaces {
		go monitor(iface)
	}

	time.Sleep(300 * time.Second)
}
