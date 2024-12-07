package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop() // always clean up
	handle, err := pcap.OpenLive("en0", 1600, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	var filter string = "tcp"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	// Open the file for writing
	file, err := os.Create("output.txt")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	//file for analyzing
	if len(os.Args) < 3 {
		fmt.Println("Usage: sudo ./packetsniffer <filename> <search_string>")
		os.Exit(1)
	}

	fileToReadName := os.Args[1]
	searchString := os.Args[2]
	//0 indicates don't include
	PortInclude := 0
	if len(os.Args) >= 3 {
		PortInclude = os.Args[3]
	}
	//0 indicates don't include
	SeqInclude := 0
	if len(os.Args) >= 4 {
		SeqInclude = os.Args[4]
	}

	for start := time.Now(); time.Since(start) < time.Second; {
		//packet is just 1 packet in an iterable of packets.
		for packet := range packetSource.Packets() {
			// Process packet here
			// Check for the TCP layer
			//tcpLayer is
			tcpLayer := packet.Layer(layers.LayerTypeTCP)
			if tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)

				// Write TCP information directly to file
				options(file, PortInclude, SeqInclude, tcp)

				// If there's payload, write it to file
				if len(tcp.Payload) > 0 {
					fmt.Fprintf(file, "Payload: %s\n", string(tcp.Payload))
				}

				// Add a separator between packets
				fmt.Fprintln(file, "----------------------------------------")
			}
			//breaks the for loops after 10 seconds
			if time.Since(start) > 10*time.Second {
				break
			}
		}

	}

	fileToRead, err := os.Open(fileToReadName)
	if err != nil {
		fmt.Println("Error opening file:", err)
		os.Exit(1)
	}
	defer fileToRead.Close()

	scanner := bufio.NewScanner(fileToRead)
	lineNumber := 1

	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, searchString) {
			fmt.Printf("Line %d: %s\n", lineNumber, line)
		}
		lineNumber++
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading file:", err)
		os.Exit(1)
	}

}

func options(File io.Writer, IncludePort int, IncludeSequence int, tcp packetSource.Packets()) {
	fmt.Fprintf(File, "From src port: %d to dst port: %d\n", tcp.SrcPort, tcp.DstPort)
	fmt.Fprintf(File, "Sequence number: %d\n", tcp.Seq)
}
