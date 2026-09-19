package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"golang.org/x/text/encoding/korean"
	"golang.org/x/text/transform"
)

// 프록시에서 제외할 요청 헤더 (PHP의 host, content-length, accept-encoding)
var skipHeaders = map[string]bool{
	"host":            true,
	"content-length":  true,
	"accept-encoding": true,
}

// PHP의 CURLOPT_SSL_VERIFYPEER=false, CURLOPT_SSL_VERIFYHOST=false, CURLOPT_TIMEOUT=15 재현.
// InsecureSkipVerify=true 는 보안상 위험하므로, 가능하면 검증을 켜는 것을 권장.
var httpClient = &http.Client{
	Timeout: 15 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
}

func handler(ctx context.Context, req events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	// 1. hostname 파라미터 추출 및 검증
	hostname := req.QueryStringParameters["hostname"]
	if hostname == "" {
		return events.APIGatewayV2HTTPResponse{
			StatusCode: 400,
			Headers:    map[string]string{"Content-Type": "text/plain; charset=UTF-8"},
			Body:       "Error: 'hostname' parameter is missing.",
		}, nil
	}

	// 2. 하위 경로 추출
	//    Function URL / HTTP API($default 스테이지)에서는 RawPath에 스테이지 접두어가 없음.
	//    스테이지/베이스 경로가 붙는 구성이면 BASE_PATH 환경변수로 잘라냄. (예: BASE_PATH=/prod)
	subPath := req.RawPath
	if base := os.Getenv("BASE_PATH"); base != "" {
		subPath = strings.TrimPrefix(subPath, base)
	}

	// 3. Query String에서 hostname 파라미터만 제거 (나머지 파라미터의 URL 인코딩은 원본 그대로 보존)
	strippedQuery := stripHostname(req.RawQueryString)

	// 4. 최종 타겟 URL 조립 (https 고정)
	targetURL := "https://" + hostname + subPath
	if strippedQuery != "" {
		targetURL += "?" + strippedQuery
	}

	// 5. HTTP Method & RAW Body
	method := req.RequestContext.HTTP.Method
	bodyBytes := []byte(req.Body)
	if req.IsBase64Encoded {
		if decoded, err := base64.StdEncoding.DecodeString(req.Body); err == nil {
			bodyBytes = decoded
		}
	}

	// 6. 업스트림 요청 생성
	var bodyReader io.Reader
	if method != http.MethodGet && len(bodyBytes) > 0 {
		bodyReader = bytes.NewReader(bodyBytes)
	}
	upstreamReq, err := http.NewRequestWithContext(ctx, method, targetURL, bodyReader)
	if err != nil {
		return badGateway(err.Error(), targetURL), nil
	}

	// 요청 헤더 복사 (제외 대상 제외)
	for k, v := range req.Headers {
		if skipHeaders[strings.ToLower(k)] {
			continue
		}
		upstreamReq.Header.Set(k, v)
	}

	// 7. cURL 실행에 해당
	resp, err := httpClient.Do(upstreamReq)
	if err != nil {
		// PHP의 $response === false + curl_error() 재현
		return badGateway(err.Error(), targetURL), nil
	}
	defer resp.Body.Close()

	rawResp, err := io.ReadAll(resp.Body)
	if err != nil {
		return badGateway(err.Error(), targetURL), nil
	}

	// 9. 응답 본문을 UTF-8로 정규화 (이미 UTF-8이면 그대로, 아니면 CP949로 간주해 변환)
	utf8Body := toUTF8(rawResp)

	// 10. 최종 출력 (업스트림 상태코드 그대로 반환, Content-Type은 원본 미디어 타입 유지 + charset=UTF-8)
	return events.APIGatewayV2HTTPResponse{
		StatusCode: resp.StatusCode,
		Headers: map[string]string{
			"Content-Type": buildContentType(resp.Header.Get("Content-Type")),
		},
		Body: utf8Body,
	}, nil
}

// stripHostname 은 raw query string에서 hostname 파라미터만 제거한다.
// 정규식 대신 & 단위로 분해/재조립하여 다른 파라미터의 원본 인코딩을 훼손하지 않는다.
func stripHostname(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}
	parts := strings.Split(rawQuery, "&")
	kept := make([]string, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			continue
		}
		key := p
		if i := strings.IndexByte(p, '='); i >= 0 {
			key = p[:i]
		}
		if key == "hostname" {
			continue
		}
		kept = append(kept, p)
	}
	return strings.Join(kept, "&")
}

// toUTF8 은 응답 본문을 UTF-8 문자열로 반환한다.
//   - 이미 유효한 UTF-8이면 변환 없이 원본 그대로 반환한다.
//   - 그렇지 않으면 CP949(EUC-KR/Windows-949)로 간주하고 UTF-8로 변환한다.
//
// 순수 ASCII는 UTF-8/CP949 양쪽 모두 유효하므로 어느 경로로 가도 결과가 동일하고,
// 한글이 포함된 CP949 바이트열은 대부분 유효한 UTF-8이 아니므로 CP949 변환 경로를 탄다.
func toUTF8(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	out, _, err := transform.Bytes(korean.EUCKR.NewDecoder(), b)
	if err != nil {
		// 변환 실패 시 best-effort로 원본 반환
		return string(b)
	}
	return string(out)
}

// buildContentType 은 업스트림 Content-Type의 미디어 타입/기타 파라미터는 유지하고
// charset만 UTF-8로 강제한다. (본문을 항상 UTF-8로 변환하므로)
//
//	application/json; charset=EUC-KR -> application/json; charset=UTF-8
//	application/json                 -> application/json; charset=UTF-8
//
// 업스트림에 Content-Type이 없거나 파싱에 실패하면 text/plain; charset=UTF-8 로 대체한다.
func buildContentType(upstream string) string {
	mediaType, params, err := mime.ParseMediaType(upstream)
	if err != nil {
		// 헤더가 비어 있거나("mime: no media type") 형식이 잘못된 경우
		return "text/plain; charset=UTF-8"
	}
	if params == nil {
		params = map[string]string{}
	}
	params["charset"] = "UTF-8" // 기존 charset(대소문자 무관)이 있으면 덮어씀
	return mime.FormatMediaType(mediaType, params)
}

func badGateway(curlError, targetURL string) events.APIGatewayV2HTTPResponse {
	return events.APIGatewayV2HTTPResponse{
		StatusCode: 502,
		Headers:    map[string]string{"Content-Type": "text/plain; charset=UTF-8"},
		Body: fmt.Sprintf("Proxy Error (502 Bad Gateway): %s\nAttempted Target URL: %s",
			curlError, targetURL),
	}
}

func main() {
	lambda.Start(handler)
}
