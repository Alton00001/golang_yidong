package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	windowSize int
	queueNum   int
)

func modifyWindow(packet gopacket.Packet) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}

	ip, _ := ipLayer.(*layers.IPv4)

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}

	tcp, _ := tcpLayer.(*layers.TCP)

	if tcp.SYN {
		// 设置 TCP 窗口大小
        	tcp.Window = uint16(windowSize)

        	// 计算 IPv4 报文的校验和
        	ipChecksum := layers.IPv4Checksum(ip.LayerContents())
        	ip.Checksum = ipChecksum

	        // 计算 TCP 报文的校验和
	        tcpChecksum := layers.TCPChecksum(ip, tcp)
	        tcp.SetNetworkLayerForChecksum(ip)
	        tcp.SetNetworkLayerForChecksum(ip)
	        tcp.Checksum = tcpChecksum
	}
}

func main() {
	flag.IntVar(&windowSize, "w", 4, "TCP Window Size")
	flag.IntVar(&queueNum, "q", 0, "iptables Queue Num")
	flag.Parse()

	handle, err := pcap.OpenLive("eth0", 1600, true, pcap.BlockForever)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening device: %v\n", err)
		os.Exit(1)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter(fmt.Sprintf("tcp port %d", queueNum)); err != nil {
		fmt.Fprintf(os.Stderr, "Error setting BPF filter: %v\n", err)
		os.Exit(1)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetChan := packetSource.Packets()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		for {
			select {
			case packet := <-packetChan:
				modifyWindow(packet)
			case <-sig:
				fmt.Println("Exiting...")
				os.Exit(0)
			}
		}
	}()

	fmt.Println("Starting packet processing...")
	<-sig
}
