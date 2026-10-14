// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package spdm

import (
	"encoding/binary"
	"fmt"
)

const (
	requestGetVersion            = 0x84
	responseVersion              = 0x04
	requestGetCapabilities       = 0xe1
	responseCapabilities         = 0x61
	requestNegotiateAlgorithms   = 0xe3
	responseAlgorithms           = 0x63
	requestGetMeasurements       = 0xe0
	responseMeasurements         = 0x60
	measurementSpecificationDMTF = 0x01
	measurementOperationAll      = 0xff
	generateSignature            = 0x01
)

type negotiatedAlgorithms struct {
	version         Version
	baseHash        BaseHashAlgorithm
	baseAsym        BaseAsymAlgorithm
	measurementHash MeasurementHashAlgorithm
}

type parsedTranscript struct {
	algorithms     negotiatedAlgorithms
	transcript     []byte
	signature      []byte
	requesterNonce []byte
	responderNonce []byte
	slot           uint8
	measurements   []MeasurementBlock
}

func parseSignedMeasurements(evidence Evidence, limits Limits) (*parsedTranscript, error) {
	if len(evidence.SignedMeasurements) == 0 || len(evidence.SignedMeasurements) > limits.MaxSignedMeasurementsBytes {
		return nil, verificationError(ErrorMalformed, "signed measurements size is invalid")
	}

	data := evidence.SignedMeasurements
	offset := 0
	var algorithms negotiatedAlgorithms
	if len(data) >= 2 && data[1] == requestGetVersion {
		var err error
		algorithms, offset, err = parseVCA(data, 0)
		if err != nil {
			return nil, err
		}
		if offset > limits.MaxVCABytes {
			return nil, verificationError(ErrorMalformed, "embedded VCA exceeds limit")
		}
		if algorithms.version != Version12 {
			return nil, verificationError(ErrorMalformed, "VCA is included in signed measurements for SPDM %x", algorithms.version)
		}
		if len(evidence.VCATranscript) != 0 {
			return nil, verificationError(ErrorMalformed, "separate VCA is forbidden for SPDM 1.2")
		}
	} else {
		if len(evidence.VCATranscript) == 0 || len(evidence.VCATranscript) > limits.MaxVCABytes {
			return nil, verificationError(ErrorMalformed, "separate VCA is required for SPDM 1.0/1.1")
		}
		var err error
		algorithms, offset, err = parseVCA(evidence.VCATranscript, 0)
		if err != nil {
			return nil, err
		}
		if offset != len(evidence.VCATranscript) {
			return nil, verificationError(ErrorMalformed, "trailing bytes after separate VCA")
		}
		if algorithms.version == Version12 {
			return nil, verificationError(ErrorMalformed, "SPDM 1.2 VCA must be included in signed measurements")
		}
		offset = 0
	}

	requestSize, requesterNonce, slot, err := parseMeasurementRequest(data[offset:], algorithms.version)
	if err != nil {
		return nil, err
	}
	offset += requestSize
	responseEnd, responderNonce, blocks, err := parseMeasurementResponse(data, offset, algorithms, slot, limits)
	if err != nil {
		return nil, err
	}
	signatureSize := signatureSize(algorithms.baseAsym)
	if responseEnd+signatureSize != len(data) {
		return nil, verificationError(ErrorMalformed, "signed measurements has %d trailing or missing bytes", len(data)-(responseEnd+signatureSize))
	}

	return &parsedTranscript{
		algorithms: algorithms, transcript: append([]byte(nil), data[:responseEnd]...),
		signature:      append([]byte(nil), data[responseEnd:]...),
		requesterNonce: requesterNonce, responderNonce: responderNonce,
		slot: slot, measurements: blocks,
	}, nil
}

func parseVCA(data []byte, offset int) (negotiatedAlgorithms, int, error) {
	var result negotiatedAlgorithms
	if err := expectHeader(data, offset, Version10, requestGetVersion); err != nil {
		return result, offset, err
	}
	offset += 4
	if len(data)-offset < 6 || data[offset+1] != responseVersion {
		return result, offset, verificationError(ErrorMalformed, "missing VERSION response")
	}
	versionCount := int(data[offset+5])
	if data[offset] != byte(Version10) {
		return result, offset, verificationError(ErrorMalformed, "VERSION response must use SPDM 1.0 header")
	}
	versionResponseSize := 6 + versionCount*2
	if versionCount == 0 || len(data)-offset < versionResponseSize {
		return result, offset, verificationError(ErrorMalformed, "truncated VERSION response")
	}
	advertised := data[offset+6 : offset+versionResponseSize]
	offset += versionResponseSize
	if len(data)-offset < 4 {
		return result, offset, verificationError(ErrorMalformed, "missing GET_CAPABILITIES request")
	}
	version := Version(data[offset])
	if version != Version10 && version != Version11 && version != Version12 {
		return result, offset, verificationError(ErrorUnsupported, "SPDM version 0x%x", version)
	}
	found := false
	for index := 1; index < len(advertised); index += 2 {
		if advertised[index] == byte(version) {
			found = true
		}
	}
	if !found {
		return result, offset, verificationError(ErrorMalformed, "selected version was not advertised")
	}
	requestCapabilitySize := 12
	responseCapabilitySize := 12
	if version == Version10 {
		requestCapabilitySize = 4
	}
	if version >= Version12 {
		requestCapabilitySize = 20
		responseCapabilitySize = 20
	}
	if err := expectHeader(data, offset, version, requestGetCapabilities); err != nil {
		return result, offset, err
	}
	if len(data)-offset < requestCapabilitySize {
		return result, offset, verificationError(ErrorMalformed, "truncated GET_CAPABILITIES request")
	}
	offset += requestCapabilitySize
	if err := expectHeader(data, offset, version, responseCapabilities); err != nil {
		return result, offset, err
	}
	if len(data)-offset < responseCapabilitySize {
		return result, offset, verificationError(ErrorMalformed, "truncated CAPABILITIES response")
	}
	if binary.LittleEndian.Uint32(data[offset+8:offset+12])&0x18 != 0x10 {
		return result, offset, verificationError(ErrorMalformed, "responder does not support signed measurements")
	}
	offset += responseCapabilitySize

	requestLength, err := lengthDelimitedMessage(data, offset, version, requestNegotiateAlgorithms, 32)
	if err != nil {
		return result, offset, err
	}
	request := data[offset : offset+requestLength]
	if err := validateAlgorithmMessage(request, 32); err != nil {
		return result, offset, err
	}
	offset += requestLength
	responseLength, err := lengthDelimitedMessage(data, offset, version, responseAlgorithms, 36)
	if err != nil {
		return result, offset, err
	}
	response := data[offset : offset+responseLength]
	if err := validateAlgorithmMessage(response, 36); err != nil {
		return result, offset, err
	}
	for responseOffset := 36; responseOffset < len(response); responseOffset += 4 {
		kind := response[responseOffset]
		selected := binary.LittleEndian.Uint16(response[responseOffset+2 : responseOffset+4])
		offered := uint16(0)
		for requestOffset := 32; requestOffset < len(request); requestOffset += 4 {
			if request[requestOffset] == kind {
				offered = binary.LittleEndian.Uint16(request[requestOffset+2 : requestOffset+4])
			}
		}
		if selected == 0 || selected&(selected-1) != 0 || selected&offered != selected {
			return result, offset, verificationError(ErrorMalformed, "algorithm structure selection was not offered or is ambiguous")
		}
	}
	if response[6] != measurementSpecificationDMTF || request[6]&response[6] == 0 {
		return result, offset, verificationError(ErrorUnsupported, "measurement specification negotiation")
	}
	selectedAsym := binary.LittleEndian.Uint32(response[12:16])
	selectedHash := binary.LittleEndian.Uint32(response[16:20])
	if selectedAsym&binary.LittleEndian.Uint32(request[8:12]) != selectedAsym || selectedHash&binary.LittleEndian.Uint32(request[12:16]) != selectedHash {
		return result, offset, verificationError(ErrorMalformed, "selected algorithms were not offered")
	}
	result = negotiatedAlgorithms{
		version:         version,
		measurementHash: measurementHashAlgorithm(binary.LittleEndian.Uint32(response[8:12])),
		baseAsym:        baseAsymAlgorithm(binary.LittleEndian.Uint32(response[12:16])),
		baseHash:        baseHashAlgorithm(binary.LittleEndian.Uint32(response[16:20])),
	}
	if result.measurementHash == "" || result.baseAsym == "" || result.baseHash == "" {
		return result, offset, verificationError(ErrorUnsupported, "negotiated algorithm selection")
	}
	offset += responseLength
	return result, offset, nil
}

func validateAlgorithmMessage(message []byte, fixed int) error {
	if message[fixed-4] != 0 || message[fixed-3] != 0 {
		return verificationError(ErrorUnsupported, "extended algorithms unsupported")
	}
	offset := fixed
	seen := map[byte]bool{}
	for count := 0; count < int(message[2]); count++ {
		if len(message)-offset < 2 {
			return verificationError(ErrorMalformed, "truncated algorithm structure")
		}
		kind, counts := message[offset], message[offset+1]
		if seen[kind] {
			return verificationError(ErrorMalformed, "duplicate algorithm structure")
		}
		seen[kind] = true
		if kind < 2 || kind > 5 || counts != 0x20 {
			return verificationError(ErrorUnsupported, "unsupported algorithm structure")
		}
		offset += 4
		if offset > len(message) {
			return verificationError(ErrorMalformed, "truncated algorithm selection")
		}
	}
	if offset != len(message) {
		return verificationError(ErrorMalformed, "algorithm length/count mismatch")
	}
	return nil
}

func parseMeasurementRequest(data []byte, version Version) (int, []byte, uint8, error) {
	requestSize := 36
	if version >= Version11 {
		requestSize++
	}
	if len(data) < requestSize {
		return 0, nil, 0, verificationError(ErrorMalformed, "truncated GET_MEASUREMENTS request")
	}
	if err := expectHeader(data, 0, version, requestGetMeasurements); err != nil {
		return 0, nil, 0, err
	}
	if data[2]&generateSignature == 0 || data[2]&^byte(3) != 0 || data[3] != measurementOperationAll {
		return 0, nil, 0, verificationError(ErrorMalformed, "GET_MEASUREMENTS must request all measurements and a signature")
	}
	slot := uint8(0)
	if version >= Version11 {
		if data[36] > 7 {
			return 0, nil, 0, verificationError(ErrorUnsupported, "unsupported certificate slot")
		}
		slot = data[36]
	}
	return requestSize, append([]byte(nil), data[4:36]...), slot, nil
}

func parseMeasurementResponse(data []byte, offset int, algorithms negotiatedAlgorithms, slot uint8, limits Limits) (int, []byte, []MeasurementBlock, error) {
	if len(data)-offset < 8 {
		return 0, nil, nil, verificationError(ErrorMalformed, "truncated MEASUREMENTS response")
	}
	if err := expectHeader(data, offset, algorithms.version, responseMeasurements); err != nil {
		return 0, nil, nil, err
	}
	if algorithms.version >= Version11 && data[offset+3]&0x0f != slot {
		return 0, nil, nil, verificationError(ErrorMalformed, "MEASUREMENTS response slot does not match request")
	}
	blockCount := int(data[offset+4])
	recordLength := int(data[offset+5]) | int(data[offset+6])<<8 | int(data[offset+7])<<16
	if recordLength > limits.MaxMeasurementRecordBytes || blockCount > limits.MaxMeasurementBlocks {
		return 0, nil, nil, verificationError(ErrorMalformed, "measurement record exceeds configured limits")
	}
	recordStart := offset + 8
	recordEnd := recordStart + recordLength
	if recordEnd > len(data) {
		return 0, nil, nil, verificationError(ErrorMalformed, "truncated measurement record")
	}
	blocks, err := parseMeasurementBlocks(data[recordStart:recordEnd], blockCount, limits)
	if err != nil {
		return 0, nil, nil, err
	}
	for _, block := range blocks {
		if !block.RawBitStream {
			size := 32
			if algorithms.measurementHash == MeasurementHashSHA384 {
				size = 48
			}
			if algorithms.measurementHash == MeasurementHashRaw || len(block.Value) != size {
				return 0, nil, nil, verificationError(ErrorMalformed, "measurement digest length/algorithm mismatch")
			}
		}
	}
	if len(data)-recordEnd < 34 {
		return 0, nil, nil, verificationError(ErrorMalformed, "truncated MEASUREMENTS nonce or opaque length")
	}
	// The responder nonce is an authenticated observation, not the Verifier
	// challenge. Freshness compares only the signed requester nonce.
	responderNonce := append([]byte(nil), data[recordEnd:recordEnd+32]...)
	opaqueLength := int(binary.LittleEndian.Uint16(data[recordEnd+32 : recordEnd+34]))
	if opaqueLength > limits.MaxOpaqueBytes || recordEnd+34+opaqueLength > len(data) {
		return 0, nil, nil, verificationError(ErrorMalformed, "invalid MEASUREMENTS opaque-data length")
	}
	return recordEnd + 34 + opaqueLength, responderNonce, blocks, nil
}

func parseMeasurementBlocks(data []byte, expectedCount int, limits Limits) ([]MeasurementBlock, error) {
	blocks := make([]MeasurementBlock, 0, expectedCount)
	seen := make(map[uint8]struct{}, expectedCount)
	for offset := 0; offset < len(data); {
		if len(blocks) >= limits.MaxMeasurementBlocks || len(blocks) >= expectedCount {
			return nil, verificationError(ErrorMalformed, "measurement block count exceeds limit")
		}
		if len(data)-offset < 4 {
			return nil, verificationError(ErrorMalformed, "truncated measurement block header")
		}
		index := data[offset]
		if _, exists := seen[index]; exists {
			return nil, verificationError(ErrorMalformed, "duplicate measurement block index %d", index)
		}
		seen[index] = struct{}{}
		specification := data[offset+1]
		if specification != measurementSpecificationDMTF {
			return nil, verificationError(ErrorUnsupported, "unsupported measurement specification")
		}
		valueLength := int(binary.LittleEndian.Uint16(data[offset+2 : offset+4]))
		offset += 4
		if valueLength > limits.MaxMeasurementValueBytes || offset+valueLength > len(data) {
			return nil, verificationError(ErrorMalformed, "invalid measurement block %d length", index)
		}
		encodedValue := data[offset : offset+valueLength]
		offset += valueLength
		block := MeasurementBlock{Index: index, MeasurementSpecification: specification, Value: append([]byte(nil), encodedValue...)}
		if specification == measurementSpecificationDMTF {
			if len(encodedValue) < 3 {
				return nil, verificationError(ErrorMalformed, "DMTF measurement block %d is truncated", index)
			}
			declared := int(binary.LittleEndian.Uint16(encodedValue[1:3]))
			if declared != len(encodedValue)-3 {
				return nil, verificationError(ErrorMalformed, "DMTF measurement block %d value length mismatch", index)
			}
			block.ValueType = encodedValue[0] & 0x7f
			block.RawBitStream = encodedValue[0]&0x80 != 0
			block.Value = append([]byte(nil), encodedValue[3:]...)
		}
		blocks = append(blocks, block)
	}
	if len(blocks) != expectedCount {
		return nil, verificationError(ErrorMalformed, "measurement block count is %d, want %d", len(blocks), expectedCount)
	}
	return blocks, nil
}

func expectHeader(data []byte, offset int, version Version, code byte) error {
	if offset < 0 || len(data)-offset < 4 {
		return verificationError(ErrorMalformed, "truncated SPDM message header")
	}
	if Version(data[offset]) != version || data[offset+1] != code {
		return verificationError(ErrorMalformed, "unexpected SPDM message at offset %d: version=0x%x code=0x%x", offset, data[offset], data[offset+1])
	}
	return nil
}

func lengthDelimitedMessage(data []byte, offset int, version Version, code byte, minimum int) (int, error) {
	if err := expectHeader(data, offset, version, code); err != nil {
		return 0, err
	}
	if len(data)-offset < 6 {
		return 0, verificationError(ErrorMalformed, "truncated length-delimited SPDM message")
	}
	length := int(binary.LittleEndian.Uint16(data[offset+4 : offset+6]))
	if length < minimum || length > len(data)-offset {
		return 0, verificationError(ErrorMalformed, "invalid SPDM message length %d", length)
	}
	return length, nil
}

func baseHashAlgorithm(bits uint32) BaseHashAlgorithm {
	switch bits {
	case 1 << 0:
		return BaseHashSHA256
	case 1 << 1:
		return BaseHashSHA384
	default:
		return ""
	}
}

func baseAsymAlgorithm(bits uint32) BaseAsymAlgorithm {
	switch bits {
	case 1 << 4:
		return BaseAsymECDSAP256
	case 1 << 7:
		return BaseAsymECDSAP384
	default:
		return ""
	}
}

func measurementHashAlgorithm(bits uint32) MeasurementHashAlgorithm {
	switch bits {
	case 1 << 0:
		return MeasurementHashRaw
	case 1 << 1:
		return MeasurementHashSHA256
	case 1 << 2:
		return MeasurementHashSHA384
	default:
		return ""
	}
}

func signatureSize(algorithm BaseAsymAlgorithm) int {
	if algorithm == BaseAsymECDSAP256 {
		return 64
	}
	if algorithm == BaseAsymECDSAP384 {
		return 96
	}
	return 0
}

func (v Version) String() string {
	return fmt.Sprintf("%d.%d", uint8(v)>>4, uint8(v)&0x0f)
}
