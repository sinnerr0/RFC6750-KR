# RFC6750_KR

IETF(국제 표준화 기구)의 RFC 6750(The OAuth 2.0 Authorization Framework: Bearer Token Usage)를 공부하기 위함

# The OAuth 2.0 Authorization Framework: Bearer Token Usage

## Abstract

이 사양은 OAuth 2.0 보호 리소스에 액세스하기 위해 HTTP 요청에서 Bearer 토큰을 사용하는 방법을 설명합니다. bearer 토큰을 소유 한 모든 당사자는 이를 사용하여 관련 리소스에 액세스 할 수 있습니다 (암호화 키 보유를 증명하지 않음). 오용을 방지하기 위해 보유자 토큰은 보관 및 운송시 공개되지 않도록 보호해야합니다.

## Status of This Memo

This is an Internet Standards Track document.

This document is a product of the Internet Engineering Task Force(IETF). It represents the consensus of the IETF community. It has received public review and has been approved for publication by the Internet Engineering Steering Group (IESG). Further information on Internet Standards is available in Section 2 of RFC 5741.

Information about the current status of this document, any errata, and how to provide feedback on it may be obtained at http://www.rfc-editor.org/info/rfc6750.

## Copyright Notice

Copyright (c) 2012 IETF Trust and the persons identified as the document authors. All rights reserved.

This document is subject to BCP 78 and the IETF Trust's Legal Provisions Relating to IETF Documents(http://trustee.ietf.org/license-info) in effect on the date of publication of this document. Please review these documents carefully, as they describe your rights and restrictions with respect to this document. Code Components extracted from this document must include Simplified BSD License text as described in Section 4.e of the Trust Legal Provisions and are provided without warranty as described in the Simplified BSD License.

# Table of Content

- [1. 소개](#1-소개)
  - [1.1. Notational Conventions](#11-notational-conventions)
  - [1.2. 술어](#12-술어)
  - [1.3. 개요](#13-개요)
- [2. 인증 된 요청](#2-인증-된-요청)
  - [2.1. 승인 요청 헤더 필드](#21-승인-요청-헤더-필드)
  - [2.2. Form-Encoded 본문 매개 변수](#22-form-encoded-본문-매개-변수)
  - [2.3. URI 쿼리 매개 변수](#23-uri-쿼리-매개-변수)
- [3. WWW-Authenticate 응답 헤더 필드](#3-www-authenticate-응답-헤더-필드)
  - [3.1. 오류 코드](#31-오류-코드)
- [4. 액세스 토큰 응답 예제](#4-액세스-토큰-응답-예제)
- [5. 보안 고려 사항](#5-보안-고려-사항)
  - [5.1. 보안 위협](#51-보안-위협)
  - [5.2. 위협 완화](#52-위협-완화)
  - [5.3. 권장 사항 요약](#53-권장-사항-요약)
- [6. IANA Considerations](#6-iana-considerations)
  - [6.1. OAuth Access Token Type Registration](#61-oauth-access-token-type-registration)
    - [6.1.1. The "Bearer" OAuth Access Token Type](#611-the-bearer-oauth-access-token-type)
  - [6.2. OAuth Extensions Error Registration](#62-oauth-extensions-error-registration)
    - [6.2.1. The "invalid_request" Error Value](#621-the-invalid_request-error-value)
    - [6.2.2. The "invalid_token" Error Value](#622-the-invalid_token-error-value)
    - [6.2.3. The "insufficient_scope" Error Value](#623-the-insufficient_scope-error-value)
- [7. References](#7-references)
  - [7.1. Normative References](#71-normative-references)
  - [7.2. Informative References](#72-informative-references)
- [Appendix A. Acknowledgements](#appendix-a-acknowledgements)

<!-- /code_chunk_output -->

# 1. 소개

OAuth를 사용하면 클라이언트가 리소스 소유자의 자격 증명을 직접 사용하는 대신 "OAuth 2.0 인증 프레임 워크"[RFC6749]에 "클라이언트에 발급 된 액세스 권한을 나타내는 문자열"로 정의 된 액세스 토큰을 가져 와서 보호된 리소스에 액세스 할 수 있습니다.

토큰은 자원 소유자의 권한 부여를 받아 권한 부여 서버에서 클라이언트에 발급됩니다. 클라이언트는 액세스 토큰을 사용하여 리소스 서버에서 호스팅하는 보호 된 리소스에 액세스합니다. 이 사양은 OAuth 액세스 토큰이 Bearer 토큰 일 때 보호 된 리소스 요청을 만드는 방법을 설명합니다.

이 사양은 TLS (Transport Layer Security) [RFC5246]를 사용하여 보호된 리소스에 액세스하는 HTTP/1.1 [RFC2616]을 통한 베어러 토큰 사용을 정의합니다. TLS는이 사양을 구현하고 사용하는 데 필수입니다. 다른 사양은 다른 프로토콜과 함께 사용하기 위해이 사양을 확장 할 수 있습니다. 액세스 토큰과 함께 사용하도록 설계되었지만

OAuth 2.0 인증 [RFC6749]의 결과로 OAuth 보호 리소스에 액세스하기 위해이 사양은 실제로 해당 bearer 토큰으로 보호되는 모든 리소스에 액세스하기 위해 모든 소스의 bearer 토큰과 함께 사용할 수있는 일반 HTTP 인증 방법을 정의합니다. Bearer 인증 체계는 주로 WWW-Authenticate 및 Authorization HTTP 헤더를 사용하는 서버 인증을 위한 것이지만 프록시 인증에 대한 사용을 배제하지는 않습니다.

## 1.1. Notational Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in "Key words for use in RFCs to Indicate Requirement Levels" [RFC2119].

This document uses the Augmented Backus-Naur Form (ABNF) notation of [RFC5234]. Additionally, the following rules are included from HTTP/1.1 [RFC2617]: auth-param and auth-scheme; and from "Uniform Resource Identifier (URI): Generic Syntax" [RFC3986]: URI-reference.

Unless otherwise noted, all the protocol parameter names and values are case sensitive.

## 1.2. 술어

Bearer 토큰  
토큰을 소유한 당사자 ("bearer")는 토큰을 사용할 수 있으며 또 다른 당사자가 소유하였다면 마찬가지로 토큰을 사용할 있는 방식으로 토큰을 사용할 수 있는 속성을 가진 보안 토큰입니다. bearer 토큰을 사용하는 경우 보유자가 암호화 키(소유 증명)의 소유를 증명할 필요가 없습니다.

다른 모든 용어는 "OAuth 2.0 인증 프레임 워크"[RFC6749]에 정의되어 있습니다.

## 1.3. 개요

OAuth는 클라이언트가 리소스 소유자를 대신하여 보호된 리소스에 액세스 할 수 있는 방법을 제공합니다. 일반적으로 클라이언트가 보호된 리소스에 액세스하려면 먼저 리소스 소유자로부터 권한 부여를 받은 다음 권한 부여를 액세스 토큰으로 교환해야합니다. 액세스 토큰은 권한 부여에 의해 부여 된 권한의 범위, 기간 및 기타 속성을 나타냅니다. 클라이언트는 리소스 서버에 액세스 토큰을 제공하여 보호 된 리소스에 액세스합니다. 경우에 따라 클라이언트는 먼저 리소스 소유자로부터 권한 부여를 받지 않고도 액세스 토큰을 얻기 위해 권한 부여 서버에 자신의 자격 증명을 직접 제공 할 수 있습니다.

액세스 토큰은 리소스 서버가 이해하는 단일 토큰에 대해 다른 인증 구성 (예: 사용자 이름 및 암호, assertion)을 대체하는 추상화를 제공합니다. 이러한 추상화를 통해 짧은 기간 동안 유효한 액세스 토큰을 발급 할 수 있을뿐만 아니라 광범위한 인증 체계를 이해해야 하는 리소스 서버의 필요성을 제거 할 수 있습니다.

     +--------+                               +---------------+
     |        |--(A)- Authorization Request ->|   Resource    |
     |        |                               |     Owner     |
     |        |<-(B)-- Authorization Grant ---|               |
     |        |                               +---------------+
     |        |
     |        |                               +---------------+
     |        |--(C)-- Authorization Grant -->| Authorization |
     | Client |                               |     Server    |
     |        |<-(D)----- Access Token -------|               |
     |        |                               +---------------+
     |        |
     |        |                               +---------------+
     |        |--(E)----- Access Token ------>|    Resource   |
     |        |                               |     Server    |
     |        |<-(F)--- Protected Resource ---|               |
     +--------+                               +---------------+

                     Figure 1: Abstract Protocol Flow

그림 1에 표시된 OAuth 2.0 추상화 흐름은 클라이언트, 리소스 소유자, 권한 부여 서버 및 리소스 서버 ([RFC6749]에 설명 됨) 간의 상호 작용을 설명합니다. 이 문서에는 다음 두 단계가 명시되어 있습니다.

(E) 클라이언트는 리소스 서버에서 보호된 리소스를 요청하고 액세스 토큰을 제시하여 인증합니다.

(F) 리소스 서버가 액세스 토큰의 유효성을 검사하고 유효한 경우 요청을 처리합니다.

이 문서는 또한 (D) 단계에서 반환 된 액세스 토큰에 semantic 요구 사항을 부과합니다.

# 2. 인증 된 요청

이 섹션에서는 리소스 요청의 bearer 액세스 토큰을 리소스 서버로 보내는 세 가지 방법을 정의합니다. 클라이언트는 각 요청에서 토큰을 전송하는 데 하나 이상의 방법을 사용해서는 안됩니다.

## 2.1. 승인 요청 헤더 필드

HTTP/1.1 [RFC2617]에 정의 된 "Authorization"요청 헤더 필드에서 액세스 토큰을 보낼 때 클라이언트는 "Bearer"인증 체계를 사용하여 액세스 토큰을 전송합니다.

This section defines three methods of sending bearer access tokens in resource requests to resource servers. Clients MUST NOT use more than one method to transmit the token in each request.

For example:

     GET /resource HTTP/1.1
     Host: server.example.com
     Authorization: Bearer mF_9.B5f-4.1JqM

이 체계에 대한 "Authorization"헤더 필드의 구문은 [RFC2617]의 Section 2에 정의 된 기본 체계의 사용을 따릅니다. Basic과 마찬가지로 [RFC2617]의 Section 1.2에 정의 된 일반 구문을 따르지 않지만 HTTP 1.1 [HTTP-AUTH] 용으로 개발중인 일반 인증 프레임 워크와 호환됩니다. 기존 배포를 반영하기 위해 여기에 설명 된 선호 방법을 따르지는 않습니다. Bearer 자격 증명의 구문은 다음과 같습니다.

     b64token    = 1*( ALPHA / DIGIT /
                       "-" / "." / "_" / "~" / "+" / "/" ) *"="
     credentials = "Bearer" 1*SP b64token

클라이언트는 "Bearer" HTTP 인증 체계와 함께 "Authorization"요청 헤더 필드를 사용하여 Bearer 토큰으로 인증 된 요청을 해야합니다. 리소스 서버는 이 방법을 지원해야합니다.

## 2.2. Form-Encoded 본문 매개 변수

HTTP 요청 엔티티 본문에 액세스 토큰을 보낼 때 클라이언트는 "access_token"매개 변수를 사용하여 요청 본문에 액세스 토큰을 추가합니다. 클라이언트는 다음 조건이 모두 충족되지 않는 한 이 방법을 사용해서는 안됩니다.

o HTTP 요청 엔티티 헤더는 "application/x-www-form-urlencoded"로 설정된 "Content-Type"헤더 필드를 포함합니다.

o entity-body는 HTML 4.01 [W3C.REC-html401-19991224]에 정의 된대로 "application/x-www-form-urlencoded"컨텐츠 유형의 인코딩 요구 사항을 따릅니다.

o HTTP 요청 엔티티 본문은 단일 부분입니다.

o 엔터티 본문에 인코딩 될 내용은 전적으로 ASCII [USASCII] 문자로 구성되어야합니다.

o HTTP 요청 방법은 요청 본문이 의미를 정의한 방법입니다. 특히 이것은 "GET"메소드를 사용해서는 안된다는 것을 의미합니다.

엔티티 본문은 다른 요청 특정 매개 변수를 포함 할 수 있으며, 이 경우 "access_token"매개 변수는 "&"문자를 사용하여 요청 특정 매개 변수와 적절하게 분리되어야합니다 (ASCII 코드 38).

예를 들어 클라이언트는 전송 계층 보안을 사용하여 다음 HTTP 요청을 수행합니다.

     POST /resource HTTP/1.1
     Host: server.example.com
     Content-Type: application/x-www-form-urlencoded

     access_token=mF_9.B5f-4.1JqM

"application/x-www-form-urlencoded"는 참여하는 브라우저가 "Authorization"요청 헤더 필드에 액세스 할 수 없는 애플리케이션 컨텍스트를 제외하고는 사용되지 않아야합니다. 리소스 서버는 이 방법을 지원 할 수 있습니다.

## 2.3. URI 쿼리 매개 변수

HTTP 요청 URI에서 액세스 토큰을 보낼 때 클라이언트는 "access_token"매개 변수를 사용하여 "URI (Uniform Resource Identifier): Generic Syntax"[RFC3986]에 정의 된대로 요청 URI 쿼리 구성 요소에 액세스 토큰을 추가합니다.

예를 들어 클라이언트는 전송 계층 보안을 사용하여 다음 HTTP 요청을 수행합니다.

     GET /resource?access_token=mF_9.B5f-4.1JqM HTTP/1.1
     Host: server.example.com

HTTP 요청 URI 쿼리는 다른 요청 특정 매개 변수를 포함 할 수 있으며,이 경우 "access_token"매개 변수는 "&"문자 (ASCII 코드 38)를 사용하여 요청 특정 매개 변수와 적절하게 분리되어야합니다.

예를 들면 :

    https://server.example.com/resource?access_token=mF_9.B5f-4.1JqM&p=q

URI 쿼리 매개 변수 메소드를 사용하는 클라이언트는 "no-store"옵션을 포함하는 Cache-Control 헤더도 전송해야합니다 (SHOULD). 이러한 요청에 대한 서버 성공 (2XX status) 응답은 "private"옵션이있는 Cache-Control 헤더를 포함해야합니다 (SHOULD).

액세스 토큰을 포함하는 URL이 기록될 가능성이 높은 것을 포함하여 URI 방법 ([Section 5](#5-보안-고려-사항) 참조)과 관련된 보안 약점으로 인해 "Authorization" 요청 헤더 필드 또는 HTTP 요청 엔티티 본문에서 액세스 토큰을 전송할 수 없는 경우가 아니면 사용해서는 안됩니다. 리소스 서버는 이 방법을 지원할 수 있습니다.

이 방법은 현재 사용되어 문서에 포함됩니다. 보안 결함으로 인해 사용하지 않는 것이 좋습니다 ([Section 5](#5-보안-고려-사항) 참조). "Architecture of the World Wide Web, Volume One" [W3C.REC-webarch-20041215]에 URI namespace best practices 에 반대되는 예약 된 쿼리 매개 변수 이름을 사용하기 때문입니다.

# 3. WWW-Authenticate 응답 헤더 필드

보호된 리소스 요청에 인증 자격 증명이 포함되어 있지 않거나 보호된 리소스에 대한 액세스를 가능하게 하는 액세스 토큰이 포함되지 않은 경우 리소스 서버는 HTTP "WWW-Authenticate"응답 헤더 필드를 포함해야합니다. 다른 조건에 대한 응답으로도 포함 할 수 있습니다. "WWW-Authenticate"헤더 필드는 HTTP/1.1 [RFC2617]에 정의 된 프레임 워크를 사용합니다.

이 사양에 정의된 모든 문제는 auth-scheme 값 "Bearer"를 사용해야 합니다. 이 scheme 뒤에는 하나 이상의 auth-param 값이 와야합니다. 이 사양에서 사용하거나 정의한 auth-param 속성은 다음과 같습니다. 다른 auth-param 속성도 사용할 수 있습니다.

HTTP/1.1 [RFC2617]에 설명 된 방식으로 보호 범위를 나타 내기 위해 "realm"속성이 포함될 수 있습니다. "realm"속성은 두 번 이상 나타나지 않아야 합니다.

"scope"속성은 [RFC6749]의 Section 3.3에 정의되어 있습니다. "scope"속성은 요청된 리소스에 액세스하기 위한 액세스 토큰의 필수 범위를 나타내는 대소문자 구분 범위 값의 공백으로 구분 된 목록입니다. 중앙 집중식 레지스트리가 없이 "scope"값은 권한 부여 서버에 의해 정의됩니다. "scope"값의 순서는 중요하지 않습니다. 어떤 경우에는 "scope"값이 사용됩니다.

보호 된 자원을 활용하기에 충분한 액세스 범위가 있는 새 액세스 토큰을 요청할 때. "scope"속성 사용은 선택 사항입니다. "scope"속성은 두 번 이상 나타나지 않아야합니다. "scope"값은 프로그래밍 방식으로 사용하기위한 것이며 최종 사용자에게 표시하기위한 것이 아닙니다.

다음은 두 가지 예제 범위 값입니다. 이들은 각각 OpenID Connect [OpenID.Messages] 및 OATC (Open Authentication Technology Committee) OMAP (온라인 멀티미디어 인증 프로토콜) OAuth 2.0 사용 사례에서 가져 왔습니다:

     scope="openid profile email"
     scope="urn:example:channel=HBO&urn:example:rating=G,PG-13"

보호된 리소스 요청에 액세스 토큰이 포함되어 있고 인증에 실패한 경우 리소스 서버는 액세스 요청이 거부 된 이유를 클라이언트에 제공하기 위해 "error"속성을 포함해야합니다 (SHOULD). 매개 변수 값은 [Section 3.1](#31-오류-코드)에 설명되어 있습니다. 또한 리소스 서버는 최종 사용자에게 표시되지 않는 사람이 읽을 수 있는 설명을 개발자에게 제공하기 위해 "error_description"속성을 포함 할 수 있습니다. 또한 오류를 설명하는 사람이 읽을 수있는 웹 페이지를 식별하는 절대 URI와 함께 "error_uri"속성을 포함 할 수 있습니다. "error", "error_description"및 "error_uri"속성은 두 번 이상 나타나지 않아야합니다.

"scope"속성의 값 ([RFC6749]의 Appendix A.4에 지정됨) 범위 값을 나타내는 데 %x21 / %x23-5B / %x5D-7E 및 범위 값 사이의 구분 기호에 대한 %x20 세트 외부의 문자를 포함하면 안됩니다 (MUST NOT). "error"및 "error_description"속성 값 ([RFC6749]의 Appendixes A.7 및 A.8에 지정됨) 세트 %x20-21 / %x23-5B / %x5D-7E 외부의 문자를 포함하면 안됩니다 (MUST NOT). "error_uri"속성 값 ([RFC6749]의 Appendixes A.9에 지정됨)은 URI 참조 구문을 준수해야하며 따라서 %x21 / %x23-5B / %x5D-7E 집합 외부의 문자를 포함하면 안됩니다.

예를 들어, 인증없이 보호 된 리소스 요청에 대한 응답 :

     HTTP/1.1 401 Unauthorized
     WWW-Authenticate: Bearer realm="example"

만료 된 액세스 토큰을 사용한 인증 시도로 보호 된 리소스 요청에 대한 응답으로:

     HTTP/1.1 401 Unauthorized
     WWW-Authenticate: Bearer realm="example",
                       error="invalid_token",
                       error_description="The access token expired"

## 3.1. 오류 코드

요청이 실패하면 리소스 서버는 적절한 HTTP 상태 코드 (일반적으로 400, 401, 403 또는 405)를 사용하여 응답하고 응답에 다음 오류 코드 중 하나를 포함합니다.

invalid_request  
요청에 필수 매개 변수가 누락되었거나 지원되지 않는 매개 변수 또는 매개 변수 값이 포함되어 있거나 동일한 매개 변수를 반복하거나 액세스 토큰을 포함하기 위해 둘 이상의 방법을 사용하거나 기타 형식이 잘못되었습니다. 리소스 서버는 HTTP 400 (잘못된 요청) 상태 코드로 응답해야합니다 (SHOULD).

invalid_request
제공된 액세스 토큰이 만료, 취소, 형식이 잘못되었거나 다른 이유로 유효하지 않습니다. 리소스는 HTTP 401 (Unauthorized) 상태 코드로 응답해야합니다 (SHOULD). 클라이언트는 새 액세스 토큰을 요청하고 보호된 리소스 요청을 다시 시도 할 수 있습니다.

insufficient_scope  
요청에는 액세스 토큰에서 제공하는 것보다 더 높은 권한이 필요합니다. 리소스 서버는 HTTP 403 (Bad Request) 상태 코드로 응답해야하며 보호된 리소스에 액세스하는 데 필요한 범위와 함께 "scope"속성을 포함 할 수 있습니다.

요청에 인증 정보가 없는 경우 (예: 클라이언트가 인증이 필요하다는 것을 인식하지 못했거나 지원되지 않는 인증 방법을 사용하여 시도한 경우) 리소스 서버는 오류 코드 또는 기타 오류 정보를 포함하지 않아야합니다.

예를 들면 :

     HTTP/1.1 401 Unauthorized
     WWW-Authenticate: Bearer realm="example"

# 4. 액세스 토큰 응답 예제

일반적으로 bearer 토큰은 OAuth 2.0 [RFC6749] 액세스 토큰 응답의 일부로 클라이언트에 반환됩니다. 이러한 응답의 예는 다음과 같습니다:

     HTTP/1.1 200 OK
     Content-Type: application/json;charset=UTF-8
     Cache-Control: no-store
     Pragma: no-cache

     {
       "access_token":"mF_9.B5f-4.1JqM",
       "token_type":"Bearer",
       "expires_in":3600,
       "refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA"
     }

# 5. 보안 고려 사항

이 섹션에서는 bearer 토큰 사용시 토큰 처리와 관련된 관련 보안 위협을 설명하고 이러한 위협을 완화하는 방법을 설명합니다.

## 5.1. 보안 위협

다음 목록은 특정 형태의 토큰을 사용하는 프로토콜에 대한 몇 가지 일반적인 위협을 보여줍니다. 이 위협 목록은 NIST Special Publication 800-63 [NIST800-63]을 기반으로합니다. 이 문서는 OAuth 2.0 인증 사양 [RFC6749]을 기반으로 작성되었으므로 여기 또는 관련 문서에 설명 된 위협에 대한 논의는 제외됩니다.

토큰 제조/수정: 공격자는 가짜 토큰을 생성하거나 기존 토큰의 토큰 내용 (예: 권한 부여 또는 속성 문)을 수정하여 리소스 서버가 클라이언트에 대한 부적절한 액세스 권한을 부여 할 수 있습니다. 예를 들어, 공격자는 유효 기간을 연장하기 위해 토큰을 수정할 수 있습니다. 악의적인 클라이언트는 볼 수 없어야하는 정보에 액세스하기 위해 assertion을 수정할 수 있습니다.

토큰 공개: 토큰에는 민감한 정보를 포함하는 인증 및 속성 설명이 포함될 수 있습니다.

토큰 리디렉션: 공격자는 한 리소스 서버에서 소비하기 위해 생성된 토큰을 사용하여 토큰이 자신을 위한 것이라고 잘못 생각하는 다른 리소스 서버에 액세스합니다.

토큰 재생: 공격자는 과거에 해당 리소스 서버에서 이미 사용된 토큰을 사용하려고합니다.

## 5.2. 위협 완화

디지털 서명 또는 MAC (메시지 권한 부여 코드)를 사용하여 토큰의 내용을 보호함으로써 광범위한 위협을 완화 할 수 있습니다. 또는 bearer 토큰은 정보를 직접 인코딩하는 대신 권한 부여 정보에 대한 참조를 포함 할 수 있습니다. 그러한 참조는 공격자가 추측 할 수 없어야합니다. 참조를 사용하면 권한 부여 정보에 대한 참조를 해결하기 위해 서버와 토큰 발급자간에 추가 상호 작용이 필요할 수 있습니다. 이러한 상호 작용의 메커니즘은 이 사양에 정의되어 있지 않습니다.

이 문서는 토큰의 인코딩이나 내용을 지정하지 않습니다. 따라서 토큰 무결성 보호를 보장하는 방법에 대한 자세한 권장 사항은 이 문서의 범위를 벗어납니다. 토큰 무결성 보호는 토큰이 수정되는 것을 방지하기에 충분해야합니다.

토큰 리디렉션을 처리하려면 권한 부여 서버가 의도 한 수신자 (대상)의 ID (일반적으로 단일 리소스 서버 (또는 리소스 서버 목록))를 토큰에 포함하는 것이 중요합니다. 토큰 사용을 특정 범위로 제한하는 것도 권장됩니다.

권한 부여 서버는 반드시 TLS를 구현해야합니다. 구현해야하는 버전은 시간이 지남에 따라 달라지며 구현 당시 널리 퍼진 배포 및 알려진 보안 취약점에 따라 달라집니다. 이 글을 쓰는 시점에서 TLS 버전 1.2 [RFC5246]가 가장 최신 버전이지만 실제 배포가 매우 제한되어 있으며 구현 툴킷에서 쉽게 사용할 수 없습니다. TLS 버전 1.0 [RFC2246]은 가장 널리 배포 된 버전이며 가장 광범위한 상호 운용성을 제공합니다.

토큰 공개로부터 보호하기 위해 기밀성 및 무결성 보호를 제공하는 ciphersuite와 함께 TLS [RFC5246]를 사용하여 기밀성 보호를 적용해야합니다. 이를 위해서는 클라이언트와 권한 부여 서버 간의 통신 상호 작용은 물론 클라이언트와 리소스 서버 간의 상호 작용이 기밀성과 무결성 보호를 활용해야합니다. TLS는 이 사양을 구현하고 사용하는 데 필수이므로 토큰을 방지하는 데 선호되는 접근 방식입니다.

통신 채널을 통한 공개. 클라이언트가 토큰의 내용을 관찰 할 수 없는 경우 TLS 보호의 사용과 함께 토큰 암호화를 적용해야합니다. 토큰 공개에 대한 추가 방어로서 클라이언트는 CRL (Certificate Revocation List) [RFC5280] 확인을 포함하여 보호 된 리소스에 요청할 때 TLS 인증서 체인을 확인해야합니다.

쿠키는 일반적으로 투명하게 전송됩니다. 따라서 여기에 포함 된 모든 정보는 공개 될 위험이 있습니다. 따라서 bearer 토큰은 일반 상태로 전송할 수있는 쿠키에 저장되어서는 안됩니다. 쿠키에 대한 보안 고려 사항은 "HTTP 상태 관리 메커니즘"[RFC6265]을 참조하십시오.

로드 밸런서를 사용하는 배포를 포함한 일부 배포에서는 리소스를 제공하는 실제 서버보다 먼저 리소스 서버에 대한 TLS 연결이 종료됩니다. 이로 인해 TLS 연결이 종료되는 front-end 서버와 리소스를 제공하는 back-end 서버간에 토큰이 보호되지 않을 수 있습니다. 이러한 배포에서는 front-end 서버와 back-end 서버 간의 토큰 기밀성을 보장하기 위해 충분한 조치를 취해야합니다. 토큰의 암호화는 가능한 조치 중 하나입니다.

토큰 캡처 및 재생을 처리하기 위해 다음 권장 사항이 작성됩니다. 첫째, 토큰의 수명을 제한해야합니다. 이를 달성하는 한 가지 방법은 토큰의 보호된 부분에 유효 시간 필드를 넣는 것입니다. short-lived (1 시간 이하) 토큰을 사용하면 유출되는 영향을 줄일 수 있습니다. 둘째, 클라이언트와 권한 부여 서버 사이, 클라이언트와 리소스 서버 사이의 교환에 대한 기밀성 보호가 적용되어야합니다. 결과적으로 통신 경로를 따라 도청자가 토큰 교환을 관찰 할 수 없습니다. 결과적으로 이러한 경로상의 공격자는 토큰을 재생할 수 없습니다. 또한 리소스 서버에 토큰을 제공 할 때 클라이언트는 "HTTP Over TLS"[RFC2818]의 Section 3.1에 따라 해당 리소스 서버의 ID를 확인해야합니다. 클라이언트는 보호 된 리소스에 이러한 요청을 할 때 TLS 인증서 체인의 유효성을 검사해야합니다. 인증되지 않은 권한이 없는 리소스 서버에 토큰을 제공하거나 인증서 체인의 유효성을 검사하지 않으면 공격자가 토큰을 훔쳐서 보호된 리소스에 무단 액세스 할 수 있습니다.

## 5.3. 권장 사항 요약

bearer 토큰 보호: 클라이언트 구현은 bearer 토큰이 의도하지 않은 당사자에게 유출되지 않도록해야합니다. 보호된 리소스에 액세스하는데 사용할 수 있기 때문입니다. 이는 Bearer 토큰을 사용할 때의 주요 보안 고려 사항이며 이후의 구체적인 권장 사항의 모든 기초가 됩니다.

TLS 인증서 체인 유효성 검사: 클라이언트는 보호된 리소스에 요청할 때 TLS 인증서 체인의 유효성을 검사해야합니다. 그렇게하지 않으면 DNS hijacking 공격이 토큰을 훔치고 의도하지 않은 액세스를 얻을 수 있습니다.

항상 TLS (https) 사용: 클라이언트는 bearer 토큰으로 요청할 때 항상 TLS [RFC5246] (https) 또는 이에 상응하는 전송 보안을 사용해야합니다. 그렇게하지 않으면 공격자에게 의도하지 않은 액세스를 제공 할 수있는 수 많은 공격에 토큰이 노출됩니다.

쿠키에 베어러 토큰을 저장하지 마십시오: 구현시 쿠키에 대한 기본 전송 모드인 일반 전송 모드로 전송할 수 있는 쿠키 내에 bearer 토큰을 저장하지 않아야합니다. ㅍ 토큰을 쿠키에 저장하는 구현은 교차 사이트 요청 위조에 대한 예방 조치를 취해야합니다.

단기 보유자 토큰 발행: 토큰 서버는 특히 정보 유출이 발생할 수 있는 웹 브라우저 또는 기타 환경 내에서 실행되는 클라이언트에 토큰을 발행 할 때 단기 (1 시간 이하) bearer 토큰을 발행해야합니다. 수명이 짧은 bearer 토큰을 사용하면 유출되는 영향을 줄일 수 있습니다.

범위가 지정된 bearer 토큰 발행: 토큰 서버는 대상 제한이 포함된 베어러 토큰을 발행하여 의도된 신뢰 당사자 또는 신뢰 당사자 세트로 사용 범위를 지정해야합니다.

페이지 URL에 bearer 토큰을 전달하지 마십시오. Bearer 토큰은 페이지 URL에 전달하면 안됩니다 (예 : 쿼리 문자열 매개 변수). 대신, bearer 토큰은 기밀성 조치가 취해진 HTTP 메시지 헤더 또는 메시지 본문에 전달되어야합니다. 브라우저, 웹 서버 및 기타 소프트웨어는 브라우저 기록, 웹 서버 로그 및 기타 데이터 구조에서 URL을 적절하게 보호하지 못할 수 있습니다. bearer 토큰이 페이지 URL로 전달되면 공격자가 기록 데이터, 로그 또는 기타 보안되지 않은 위치에서 토큰을 훔칠 수 있습니다.

# 6. IANA Considerations

## 6.1. OAuth Access Token Type Registration

이 규격은 [RFC6749]에 정의 된 OAuth Access Token Types registry에 다음과 같은 접근 토큰 유형을 등록한다.

### 6.1.1. The "Bearer" OAuth Access Token Type

Type name:  
Bearer

Additional Token Endpoint Response Parameters:  
(none)

HTTP Authentication Scheme(s):  
Bearer

Change controller:  
IETF

Specification document(s):  
RFC 6750

## 6.2. OAuth Extensions Error Registration

This specification registers the following error values in the OAuth Extensions Error registry defined in [RFC6749].

### 6.2.1. The "invalid_request" Error Value

Error name:  
invalid_request

Error usage location:  
Resource access error response

Related protocol extension:  
Bearer access token type

Change controller:  
IETF

Specification document(s):  
RFC 6750

### 6.2.2. The "invalid_token" Error Value

Error name:  
invalid_token

Error usage location:  
Resource access error response

Related protocol extension:  
Bearer access token type

Change controller:  
IETF

Specification document(s):  
RFC 6750

### 6.2.3. The "insufficient_scope" Error Value

Error name:  
insufficient_scope

Error usage location:  
Resource access error response

Related protocol extension:  
Bearer access token type

Change controller:  
IETF

Specification document(s):  
RFC 6750

# 7. References

## 7.1. Normative References

[RFC2119] Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, March 1997.

[RFC2246] Dierks, T. and C. Allen, "The TLS Protocol Version 1.0", RFC 2246, January 1999.

[RFC2616] Fielding, R., Gettys, J., Mogul, J., Frystyk, H., Masinter, L., Leach, P., and T. Berners-Lee, "Hypertext Transfer Protocol -- HTTP/1.1", RFC 2616, June 1999.

[RFC2617] Franks, J., Hallam-Baker, P., Hostetler, J., Lawrence, S., Leach, P., Luotonen, A., and L. Stewart, "HTTP Authentication: Basic and Digest Access Authentication", RFC 2617, June 1999.

[RFC2818] Rescorla, E., "HTTP Over TLS", RFC 2818, May 2000.

[RFC3986] Berners-Lee, T., Fielding, R., and L. Masinter, "Uniform Resource Identifier (URI): Generic Syntax", STD 66, RFC 3986, January 2005.

[RFC5234] Crocker, D. and P. Overell, "Augmented BNF for Syntax Specifications: ABNF", STD 68, RFC 5234, January 2008.

[RFC5246] Dierks, T. and E. Rescorla, "The Transport Layer Security (TLS) Protocol Version 1.2", RFC 5246, August 2008.

[RFC5280] Cooper, D., Santesson, S., Farrell, S., Boeyen, S., Housley, R., and W. Polk, "Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile", RFC 5280, May 2008.

[RFC6265] Barth, A., "HTTP State Management Mechanism", RFC 6265, April 2011.

[RFC6749] Hardt, D., Ed., "The OAuth 2.0 Authorization Framework", RFC 6749, October 2012.

[USASCII] American National Standards Institute, "Coded Character Set -- 7-bit American Standard Code for Information Interchange", ANSI X3.4, 1986.

[W3C.REC-html401-19991224] Raggett, D., Le Hors, A., and I. Jacobs, "HTML 4.01 Specification", World Wide Web Consortium Recommendation REC-html401-19991224, December 1999, <http://www.w3.org/TR/1999/REC-html401-19991224>.

[W3C.REC-webarch-20041215] Jacobs, I. and N. Walsh, "Architecture of the World Wide Web, Volume One", World Wide Web Consortium Recommendation REC-webarch-20041215, December 2004, <http://www.w3.org/TR/2004/REC-webarch-20041215>.

## 7.2. Informative References

[HTTP-AUTH] Fielding, R., Ed., and J. Reschke, Ed., "Hypertext Transfer Protocol (HTTP/1.1): Authentication", Work in Progress, October 2012.

[NIST800-63] Burr, W., Dodson, D., Newton, E., Perlner, R., Polk, T., Gupta, S., and E. Nabbus, "NIST Special Publication 800-63-1, INFORMATION SECURITY", December 2011, <http://csrc.nist.gov/publications/>.

[OMAP] Huff, J., Schlacht, D., Nadalin, A., Simmons, J., Rosenberg, P., Madsen, P., Ace, T., Rickelton-Abdi, C., and B. Boyer, "Online Multimedia Authorization Protocol: An Industry Standard for Authorized Access to Internet Multimedia Resources", April 2012, <http://www.oatc.us/Standards/Download.aspx>.

[OpenID.Messages] Sakimura, N., Bradley, J., Jones, M., de Medeiros, B.,
Mortimore, C., and E. Jay, "OpenID Connect Messages 1.0", June 2012, <http://openid.net/specs/openid-connect-messages-1_0.html>.

# Appendix A. Acknowledgements

The following people contributed to preliminary versions of this document: Blaine Cook (BT), Brian Eaton (Google), Yaron Y. Goland (Microsoft), Brent Goldman (Facebook), Raffi Krikorian (Twitter), Luke Shepard (Facebook), and Allen Tom (Yahoo!). The content and concepts within are a product of the OAuth community, the Web Resource Authorization Profiles (WRAP) community, and the OAuth Working Group. David Recordon created a preliminary version of this specification based upon an early draft of the specification that evolved into OAuth 2.0 [RFC6749]. Michael B. Jones in turn created the first version (00) of this specification using portions of David's preliminary document and edited all subsequent versions.

The OAuth Working Group has dozens of very active contributors who proposed ideas and wording for this document, including Michael Adams, Amanda Anganes, Andrew Arnott, Derek Atkins, Dirk Balfanz, John Bradley, Brian Campbell, Francisco Corella, Leah Culver, Bill de hOra, Breno de Medeiros, Brian Ellin, Stephen Farrell, Igor Faynberg, George Fletcher, Tim Freeman, Evan Gilbert, Yaron Y. Goland, Eran Hammer, Thomas Hardjono, Dick Hardt, Justin Hart, Phil Hunt, John Kemp, Chasen Le Hara, Barry Leiba, Amos Jeffries, Michael B. Jones, Torsten Lodderstedt, Paul Madsen, Eve Maler, James Manger, Laurence Miao, William J. Mills, Chuck Mortimore, Anthony Nadalin, Axel Nennker, Mark Nottingham, David Recordon, Julian Reschke, Rob Richards, Justin Richer, Peter Saint-Andre, Nat Sakimura, Rob Sayre, Marius Scurtescu, Naitik Shah, Justin Smith, Christian Stuebner, Jeremy Suriel, Doug Tangren, Paul Tarjan, Hannes Tschofenig, Franklin Tse, Sean Turner, Paul Walker, Shane Weeden, Skylar Woodward, and Zachary Zeltsan.

Authors' Addresses

Michael B. Jones  
Microsoft

EMail: mbj@microsoft.com  
URI: http://self-issued.info/

Dick Hardt  
Independent

EMail: dick.hardt@gmail.com  
URI: http://dickhardt.org/
