// MIT License
//
// Copyright (c) 2017 Stefan Wichmann
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
package main

/*
Response example:

HTTP/1.1 200 OK
HOST: 239.255.255.250:1900
EXT:
CACHE-CONTROL: max-age=100
LOCATION: http://192.168.178.241:80/description.xml
SERVER: FreeRTOS/7.4.2 UPnP/1.0 IpBridge/1.10.0
hue-bridgeid: 001788FFFE09A206
ST: upnp:rootdevice
USN: uuid:2f402f80-da50-11e1-9b23-00178809a206::upnp:rootdevice

FROM: https://developers.meethue.com/documentation/changes-bridge-discovery
*/
import "time"
import "net"
import "strings"
import "errors"
import "fmt"

const upnpTimeout = 3 * time.Second

// SSDP Payload - Make sure to keep linebreaks and indention untouched.
const ssdpPayload = `M-SEARCH * HTTP/1.1
HOST: 239.255.255.250:1900
ST: ssdp:all
MAN: %s
MX: 2

`

func upnpDiscover(man string) ([]string, int, error) {
	var responses []string
	var valid []string

	// Open listening port for incoming responses
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{Port: 1900})
	if err != nil {
		return valid, len(responses), err
	}
	socket.SetDeadline(time.Now().Add(upnpTimeout))
	defer socket.Close()

	// Send out discovery request as broadcast
	body := fmt.Sprintf(ssdpPayload, man)
	rawBody := []byte(strings.Replace(body, "\n", "\r\n", -1))
	_, err = socket.WriteToUDP(rawBody, &net.UDPAddr{IP: net.IPv4(239, 255, 255, 250), Port: 1900})
	if err != nil {
		return valid, len(responses), err
	}

	// Loop over responses until timeout hits
loop:
	for {
		// Read response
		buf := make([]byte, 8192)
		_, addr, err := socket.ReadFromUDP(buf)
		if err != nil {
			if e, ok := err.(net.Error); !ok || !e.Timeout() {
				return valid, len(responses), err //legitimate error, not a timeout.
			}
			return valid, len(responses), nil // timeout
		}

		// Response unique
		for _, host := range responses {
			if host == addr.IP.String() {
				continue loop // duplicate
			}
		}
		responses = append(responses, addr.IP.String())

		// Parse and validate response
		body := string(buf)
		val, err := ssdpResponseValid(body, addr.IP)
		if err != nil {
			return valid, len(responses), err
		}
		if !val {
			continue // Ignore response
		}

		valid = append(valid, addr.IP.String())
	}
}

func ssdpResponseValid(body string, origin net.IP) (valid bool, err error) {
	// Validate header
	if !strings.Contains(body, "HTTP/1.1 200 OK") {
		// ignore notify packages
		if strings.Contains(body, "NOTIFY * HTTP/1.1") {
			return false, nil
		}
		return false, errors.New(fmt.Sprintf("Invalid SSDP response header: %s", body))
	}

	lower := strings.ToLower(body)
	// Validate MUST fields (from UPnP Device Architecture 1.1)
	if !strings.Contains(lower, "usn") || !strings.Contains(lower, "st") {
		return false, errors.New("Invalid SSDP response")
	}

	// Hue bridges send string "IpBridge" in SERVER field
	// (see https://developers.meethue.com/documentation/hue-bridge-discovery)
	if !strings.Contains(lower, "ipbridge") {
		return false, nil
	}

	// Validate IP in LOCATION field
	if !strings.Contains(lower, "location") {
		return false, errors.New("Invalid hue bridge response")
	}
	s := strings.SplitAfter(lower, "location: ")
	location := strings.Split(s[1], "\n")[0]
	s = strings.SplitAfter(location, "http://")
	ip := strings.Split(s[1], ":")[0]

	if ip != origin.String() {
		return false, errors.New("Response and sender mismatch")
	}

	return true, nil
}
