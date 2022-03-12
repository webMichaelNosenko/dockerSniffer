package main

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/docker/distribution/context"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	client2 "github.com/docker/docker/client"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	_ "github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
)

const (
	// The same default as tcpdump.
	defaultSnapLen = 262144
)

type ContainerData struct {
	names []string
	ports []string
}

func removeDuplicateStr(strSlice []string) []string {
	allKeys := make(map[string]bool)
	var list []string
	for _, item := range strSlice {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	return list
}

func readHttpBody(rc io.ReadCloser, length int) (result string, err error) {
	defer func(rc io.ReadCloser) {
		err = rc.Close()
	}(rc)
	buf := make([]byte, length)
	_, err = rc.Read(buf)
	if err != nil && err.Error() != "EOF" {
		return "", err
	}
	result = string(buf)
	return result, err
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Some parameters are missing, please use '--name=container_name --interface=network_interface'")
		return
	}
	networkInterfaceParameter := os.Args[2]
	containerNameParameter := os.Args[1]

	containerNameParts := strings.Split(containerNameParameter, "=")

	if len(containerNameParts) <= 1 || containerNameParts[0] != "--name" {
		fmt.Println("Invalid parameters, please use '--name=container_name'")
		return
	}

	networkInterfaceParts := strings.Split(networkInterfaceParameter, "=")

	if len(networkInterfaceParts) <= 1 || networkInterfaceParts[0] != "--interface" {
		fmt.Println("Invalid parameters, please use '--interface=network_interface'")
		return
	}

	specifiedContainerName := containerNameParts[1]
	specifiedNetworkInterface := networkInterfaceParts[1]

	dockerClient, err := client2.NewClientWithOpts(client2.FromEnv)
	if err != nil {
		fmt.Println("Error creating Docker CLI client: " + err.Error())
		return
	}

	var dockerContext = context.Background()
	list, err := dockerClient.ContainerList(dockerContext, types.ContainerListOptions{
		Quiet:   true,
		Size:    false,
		All:     false,
		Latest:  false,
		Since:   "",
		Before:  "",
		Limit:   0,
		Filters: filters.Args{},
	})
	if err != nil {
		fmt.Println("Error retrieving container list: " + err.Error())
		return
	}

	var specifiedContainer ContainerData
	var containerData []ContainerData
	for i := 0; i < len(list); i++ {
		var containerNames []string
		var containerPorts []string

		for _, name := range list[i].Names {
			containerNames = append(containerNames, strings.Replace(name, "/", "", -1))
		}

		for _, port := range list[i].Ports {
			if port.PublicPort != 0 {
				containerPorts = append(containerPorts, strconv.Itoa(int(port.PublicPort)))
			}
		}

		containerPorts = removeDuplicateStr(containerPorts)
		containerNames = removeDuplicateStr(containerNames)

		newContainer := ContainerData{
			names: containerNames,
			ports: containerPorts,
		}
		containerData = append(containerData, newContainer)

		if len(specifiedContainer.ports) <= 0 && strings.Contains(strings.Join(newContainer.names, " "), specifiedContainerName) {
			specifiedContainer = newContainer
		}

		containerNames = nil
		containerPorts = nil

	}

	if len(specifiedContainer.ports) <= 0 {
		fmt.Println("No container with name " + specifiedContainerName + " found running")
		return
	}

	fmt.Println(strings.Join(specifiedContainer.names, " ") + " ports: " + strings.Join(specifiedContainer.ports, " "))
	fmt.Println("=====================")

	handle, err := pcap.OpenLive(specifiedNetworkInterface, defaultSnapLen, true,
		pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter("port " + specifiedContainer.ports[0]); err != nil {
		panic(err)
	}

	packets := gopacket.NewPacketSource(handle, handle.LinkType()).Packets()
	for packet := range packets {
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			if len(tcp.Payload) != 0 {
				reader := bufio.NewReader(bytes.NewReader(tcp.Payload))
				httpReq, err := http.ReadRequest(reader)
				if err != nil {
					continue
				}
				for header := range httpReq.Header {
					fmt.Println(header + ": " + httpReq.Header.Get(header))
				}
				fmt.Println("Origin: " + packet.NetworkLayer().NetworkFlow().Src().String() + ":" + tcp.SrcPort.String())
				fmt.Println("Host: " + httpReq.Host)
				fmt.Println("")
				httpBody := ""
				if httpBody == "" {
					err := httpReq.ParseForm()
					if err != nil {
						fmt.Println(err)
						continue
					}
					for formField := range httpReq.Form {
						httpBody += string(formField)
					}
				}
				if httpBody == "" {
					for formField := range httpReq.PostForm {
						httpBody += string(formField)
					}
				}
				if httpBody == "" && httpReq.Header.Get("content-type") == "multipart/form-data" {
					err := httpReq.ParseMultipartForm(4096)
					if err != nil {
						fmt.Println(err)
						continue
					}
					for formField := range httpReq.MultipartForm.Value {
						httpBody += string(formField)
					}
				}
				if httpBody == "" {
					reqContentLen, err := strconv.Atoi(httpReq.Header.Get("content-length"))
					if err != nil {
						fmt.Println(err)
						continue
					}
					httpBody, err = readHttpBody(httpReq.Body, reqContentLen)
					if err != nil {
						fmt.Println(err)
						continue
					}
				}
				fmt.Println(httpBody)
				fmt.Println("=====================")
			}
		}
	}

	return
}
