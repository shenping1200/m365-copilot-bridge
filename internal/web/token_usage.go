package web

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"unicode"

	tiktoken "github.com/tiktoken-go/tokenizer"
)

const (
	requestProtocolTokens    = 4
	messageProtocolTokens    = 4
	toolProtocolTokens       = 6
	toolChoiceProtocolTokens = 2
	replyPrimingTokens       = 3
	outputProtocolTokens     = 3
)

var (
	gptTokenizerOnce sync.Once
	gptTokenizer     tiktoken.Codec
	gptTokenizerErr  error
)

func getGPTTokenizer() (tiktoken.Codec, error) {
	gptTokenizerOnce.Do(func() {
		gptTokenizer, gptTokenizerErr = tiktoken.Get(tiktoken.O200kBase)
	})
	return gptTokenizer, gptTokenizerErr
}

// countTokens returns an OpenAI-style token estimate for a single text blob.
// For gpt-* models it uses the real o200k_base tokenizer (vocab embedded, no
// network); for everything else (including m365-copilot) it falls back to a
// character heuristic that skips whitespace so CJK/space handling matches the
// reference implementation used by peer gateways.
func countTokens(model, text string) int64 {
	m := strings.ToLower(strings.TrimSpace(model))
	if strings.HasPrefix(m, "gpt-") {
		if enc, err := getGPTTokenizer(); err == nil {
			if ids, _, err := enc.Encode(text); err == nil {
				return int64(len(ids))
			}
		}
	}
	return int64(heuristicTokenCount(text))
}

func heuristicTokenCount(text string) int {
	ascii, other := 0, 0
	for _, r := range text {
		if unicode.IsSpace(r) {
			continue
		}
		if r <= 0x7f {
			ascii++
		} else {
			other++
		}
	}
	if ascii == 0 && other == 0 {
		return 0
	}
	return (ascii+3)/4 + other
}

func serializedTokenCount(v any, count func(string) int) int {
	if s, ok := v.(string); ok {
		return count(s)
	}
	b, err := json.Marshal(v)
	if err != nil {
		return count(fmt.Sprint(v))
	}
	return count(string(b))
}

// estimateChatUsage tokenizes a full OpenAI-style request: every message
// (role+content+name+tool_calls) plus the tool schemas and framing overhead,
// then the completion text. Arguments are passed as any so it stays decoupled
// from the concrete oaiMsg type; messages/tools are normalized via JSON when
// they are not already []any / []map[string]any.
func estimateChatUsage(model string, messages any, tools any, output string) (int64, int64) {
	count := func(text string) int { return int(countTokens(model, text)) }
	in := int64(requestProtocolTokens + replyPrimingTokens)
	for _, m := range toAnySlice(messages) {
		in += int64(messageProtocolTokens)
		if mm, ok := m.(map[string]any); ok {
			in += int64(serializedTokenCount(mm["role"], count))
			in += int64(serializedTokenCount(mm["content"], count))
			in += int64(serializedTokenCount(mm["name"], count))
			in += int64(serializedTokenCount(mm["tool_calls"], count))
		} else {
			in += int64(serializedTokenCount(m, count))
		}
	}
	if tools != nil {
		in += int64(toolProtocolTokens) + int64(serializedTokenCount(tools, count))
	}
	out := int64(count(output))
	if output != "" {
		out += int64(outputProtocolTokens)
	}
	return in, out
}

func toAnySlice(v any) []any {
	switch t := v.(type) {
	case nil:
		return nil
	case []any:
		return t
	case []map[string]any:
		out := make([]any, len(t))
		for i, m := range t {
			out[i] = m
		}
		return out
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return nil
		}
		var s []any
		if json.Unmarshal(b, &s) == nil {
			return s
		}
		return nil
	}
}
