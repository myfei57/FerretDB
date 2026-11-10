// Copyright 2021 FerretDB Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package wiretranscript

import (
	"bufio"
	"bytes"

	"github.com/FerretDB/wire"
	"github.com/FerretDB/wire/wirebson"
)

// redactionToken replaces redacted scalar values. It is a legal BSON string,
// so every redacted document remains valid BSON.
const redactionToken = "***REDACTED***"

// defaultRedactFields are the top-level fields redacted by default
// in credential-bearing commands.
var defaultRedactFields = []string{"pwd"}

// authExchangeCommands are the commands of the authentication exchange.
// Their frames are stored as non-replayable placeholders without payloads.
var authExchangeCommands = map[string]struct{}{
	"saslStart":    {},
	"saslContinue": {},
	"authenticate": {},
}

// credentialCommands carry credential material in their request documents.
// Their sensitive fields are redacted while the rest of the document is kept.
var credentialCommands = map[string]struct{}{
	"createUser": {},
	"updateUser": {},
}

// authCommand returns the command name and true when the given body is part
// of an authentication exchange.
func authCommand(body wire.MsgBody) (string, bool) {
	msg, ok := body.(*wire.OpMsg)
	if !ok {
		return "", false
	}

	doc, err := msg.Section0()
	if err != nil {
		return "", false
	}

	cmd := doc.Command()
	_, ok = authExchangeCommands[cmd]

	return cmd, ok
}

// needsFieldRedaction returns the command name and true when the given body
// carries credential fields that must be redacted.
func needsFieldRedaction(body wire.MsgBody, fields []string) (string, bool) {
	msg, ok := body.(*wire.OpMsg)
	if !ok || len(fields) == 0 {
		return "", false
	}

	doc, err := msg.Section0()
	if err != nil {
		return "", false
	}

	cmd := doc.Command()
	if _, ok = credentialCommands[cmd]; !ok {
		return "", false
	}

	for _, f := range fields {
		if doc.Get(f) != nil {
			return cmd, true
		}
	}

	return "", false
}

// redactPayload decodes the given complete wire message payload, redacts the configured
// top-level fields of its OP_MSG section 0 document, and returns the re-encoded payload
// together with the list of actually masked field paths.
//
// The re-encoded document remains valid BSON and preserves the original field order
// and the types of all non-redacted fields. Messages that cannot be redacted safely
// (section kind 1 sequences or OP_MSG checksums, which credential commands never use)
// are returned unchanged.
func redactPayload(payload []byte, fields []string) (out []byte, masked []string, err error) {
	header, body, err := wire.ReadMessage(bufio.NewReader(bytes.NewReader(payload)))
	if err != nil {
		return nil, nil, err
	}

	msg, ok := body.(*wire.OpMsg)
	if !ok {
		return payload, nil, nil
	}

	// Redaction rebuilds a single section kind 0 message; messages with sequences
	// or checksums are not eligible.
	if msg.Flags.FlagSet(wire.OpMsgChecksumPresent) {
		return payload, nil, nil
	}

	if _, _, seq, seqErr := msg.Sections(); seqErr != nil {
		return nil, nil, seqErr
	} else if len(seq) != 0 {
		return payload, nil, nil
	}

	doc, err := msg.Section0()
	if err != nil {
		return nil, nil, err
	}

	copyDoc := doc.Copy()

	for _, f := range fields {
		if copyDoc.Get(f) != nil {
			if err = copyDoc.Replace(f, redactionToken); err != nil {
				return nil, nil, err
			}

			masked = append(masked, f)
		}
	}

	if len(masked) == 0 {
		return payload, nil, nil
	}

	newBody, err := wire.NewOpMsg(copyDoc)
	if err != nil {
		return nil, nil, err
	}

	bodyBytes, err := newBody.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}

	header.MessageLength = int32(wire.MsgHeaderLen + len(bodyBytes))

	headerBytes, err := header.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}

	return append(headerBytes, bodyBytes...), masked, nil
}

// maskDocument applies the declared masked field paths to the given decoded document,
// replacing their values with the redaction token so that recorded and live documents
// can be compared on equal terms.
func maskDocument(doc *wirebson.Document, masked []string) *wirebson.Document {
	res := doc.Copy()

	for _, path := range masked {
		// Whole-payload placeholders ("payload:<command>") never reach comparison,
		// because authentication frames are skipped; only plain field names matter here.
		if bytes.ContainsRune([]byte(path), ':') {
			continue
		}

		if res.Get(path) != nil {
			_ = res.Replace(path, redactionToken)
		}
	}

	return res
}
