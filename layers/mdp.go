// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"fmt"
	"net"
	"strconv"

	"github.com/google/gopacket"
)

const (
	MdpTlvType uint8 = iota
	MdpTlvLength
	MdpTlvDeviceInfo
	MdpTlvNetworkInfo
	MdpTlvLongitude
	MdpTlvLatitude
	MdpTlvType6
	MdpTlvType7
	MdpTlvIP          = 11
	MdpTlvUnknownBool = 13
	MdpTlvEnd         = 255
)

// MDP defines a MDP over LLC layer.
type MDP struct {
	BaseLayer
	PreambleData []byte
	DeviceInfo   string
	NetworkInfo  string
	Longitude    float64
	Latitude     float64
	Type6UUID    string
	Type7UUID    string
	IPAddress    net.IP
	Type13Bool   bool

	Type   EthernetType
	Length int
}

// LayerType returns LayerTypeMDP.
func (e *MDP) LayerType() gopacket.LayerType { return LayerTypeMDP }

// DecodeFromBytes decodes the given bytes into this layer.
func (e *MDP) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	var l int
	if len(data) < 28 {
		df.SetTruncated()
		return fmt.Errorf("MDP length %d too short", len(data))
	}
	e.Type = EthernetTypeMerakiDiscoveryProtocol
	e.Length = len(data)
	offset := 28
	e.PreambleData = data[:offset]

	for {
		if offset >= e.Length {
			break
		}
		t := data[offset]
		switch t {
		case MdpTlvDeviceInfo:
			offset += 2
			l = int(data[offset-1])
			e.Contents = append(e.Contents, data[offset-2:offset+l]...)
			e.DeviceInfo = string(data[offset : offset+l])
			offset += l
			break
		case MdpTlvNetworkInfo:
			offset += 2
			l = int(data[offset-1])
			e.NetworkInfo = string(data[offset : offset+l])
			offset += l
			break
		case MdpTlvLongitude:
			offset += 2
			l = int(data[offset-1])
			e.Longitude, _ = strconv.ParseFloat(string(data[offset:offset+l]), 64)
			offset += l
			break
		case MdpTlvLatitude:
			offset += 2
			l = int(data[offset-1])
			e.Latitude, _ = strconv.ParseFloat(string(data[offset:offset+l]), 64)
			offset += l
			break
		case MdpTlvType6:
			offset += 2
			l = int(data[offset-1])
			e.Type6UUID = string(data[offset : offset+l])
			offset += l
			break
		case MdpTlvType7:
			offset += 2
			l = int(data[offset-1])
			e.Type7UUID = string(data[offset : offset+l])
			offset += l
			break
		case MdpTlvIP:
			offset += 2
			l = int(data[offset-1])
			e.IPAddress = net.ParseIP(string(data[offset : offset+l]))
			offset += l
			break
		case MdpTlvUnknownBool:
			offset += 2
			l = int(data[offset-1])
			e.Type13Bool, _ = strconv.ParseBool(string(data[offset : offset+l]))
			offset += l
			break
		case MdpTlvEnd:
			offset = e.Length
			break
		default:
			// Skip over unknown junk
			offset += 2
			l = int(data[offset-1])
			offset += l
			break

		}
	}
	e.BaseLayer = BaseLayer{Contents: data, Payload: nil}
	return nil
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer
func (e *MDP) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	//bytes, _ := b.PrependBytes(4)
	//bytes[0] = e.Version
	//bytes[1] = byte(e.Type)
	//binary.BigEndian.PutUint16(bytes[2:], e.Length)
	return nil
}

// CanDecode returns the set of layer types that this DecodingLayer can decode.
func (e *MDP) CanDecode() gopacket.LayerClass {
	return LayerTypeMDP
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (e *MDP) NextLayerType() gopacket.LayerType {
	return e.Type.LayerType()
}

func decodeMDP(data []byte, p gopacket.PacketBuilder) error {
	e := &MDP{}
	return decodingLayerDecoder(e, data, p)
}
