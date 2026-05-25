# 개인 암호화 볼트 설계도

project FalseCrypt

모든 암호화 연산은 USAG-Lib에 기반하거나 그와 호환되도록 해야 한다.

## 데이터구조

공유하는 경우 쓰기 권한 비밀값을 빼고 필요한 데이터만 포함시킨 계정 파일로 공유

### 메타데이터
    
- 저장소ID[불변]
- 저장소명[불변]
- 사용자명[불변] (root: RW, else: R)
- 암호화됨:
	- 권한 레벨[불변]
	- 청크명 암호화 키[불변]
	- 사용자 비트 설정
	- 쓰기 비밀값

### 구조 파일
    
- 8B 연속값
- [1B 깊이][1B 플래그][6B uid]
	- 최대 폴더 깊이 255단계
	- 더미/폴더/빈파일/zstd 압축 각 1b, 권한(0-3) 2b, 사용자 설정 2b
	- 파일과 폴더 하나당 고유 uid 부여

### 이름 파일
    
- map[uid]{name, time 8B}

### 키 파일
    
- map[uid]{key, size 8B, esize 8B}
- 원문 크기와 암호화 후 크기 기록
- 비어있지 않은 파일만 존재

## 서버

- 서버는 저장소로 사용 가능한 경로들과 용량 한계를 가짐
- 서버 노드는 고유한 id 를 가짐
- 서버에는 여러 개의 저장소가 위치할 수 있고, 각 저장소는 여러 개의 물리 저장기기에 위치할 수 있음
- 쓰기 권한 인증을 위해 서버에 저장소마다 쓰기 비밀값을 공유함, 이 값은 서버만 알고 HMAC 권한 인증에 사용됨
- 노드에 새 저장소나 계정을 만들거나 지우는 행위는 별개의 서버 비밀값을 두고 쓰기 권한처럼 HMAC 검증

### 공통 동작

- 권한이 필요한 동작은 HMAC(Nonce + Timestamp + Order) 값을 헤더에 포함시켜야 함
	- hmac-set: {nonce: bytes, timestamp: int, order: string, hmac: bytes}
- 청크는 어느 노드에 쓰여질지 선호도를 설정
	- prefer: {increment: int, speed: int, capacity: int}

### 저장소 관련:
	
- GET /vault/{vault_id}
	- 해당 저장소의 존재성 확인, 없다면 타 노드에서 확인
	- 응답: 200 OK, 404 Not Found
- POST /vault/{vault_id}
	- 노드에 새 저장소 생성, 요청 시 타 노드로 전파
	- 요청: {hmac-set}
	- 쿼리: spread: bool
	- 응답: 201 Created, 401 Unauthorized, 404 Not Found, 507 Insufficient Storage
- DELETE /vault/{vault_id}
	- 노드에 저장소 삭제, 요청 시 타 노드로 전파
	- 요청: {hmac-set}
	- 쿼리: spread: bool
	- 응답: 200 OK, 401 Unauthorized, 404 Not Found
- GET /vault/{vault_id}/{chunk_id}
	- 해당 청크 반환, 없다면 타 노드로 중계하여 반환
	- 실반환 시 해시값 체크, 불일치라면 타 노드에서 가져오기
	- 쿼리: existCheck: bool
	- 응답: 200 OK {data: bytes}, 404 Not Found
- POST /vault/{vault_id}/{chunk_id}
	- 쓰기 권한을 검증하고 청크 쓰기, 적절한 노드로 전파
	- 요청: {hmac-set, prefer, data: bytes, hash: bytes}
	- 응답: 201 Created, 401 Unauthorized, 507 Insufficient Storage
- DELETE /vault/{vault_id}/{chunk_id}
	- 쓰기 권한을 검증하고 청크 지우기, 적절한 노드로 전파
	- 요청: {hmac-set}
	- 응답: 200 OK, 401 Unauthorized, 404 Not Found
	
### 계정 관련
	
- GET /account/{account_id}
	- 해당 계정의 존재성 확인, 없다면 타 노드에서 확인
	- 응답: 200 OK, 404 Not Found
- POST /account/{account_id}
	- 새 계정을 등록하고 저장소와 연결, 요청 시 타 노드로 전파
	- 요청: {hmac-set, vault_id: string, meta: bytes, struct: bytes, names: bytes, keys: bytes}
	- 쿼리: spread: bool
	- 응답: 201 Created, 401 Unauthorized, 404 Not Found, 507 Insufficient Storage
- DELETE /account/{account_id}
	- 해당 계정을 삭제, 요청 시 타 노드로 전파
	- 요청: {hmac-set}
	- 쿼리: spread: bool
	- 응답: 200 OK, 404 Not Found
- GET /account/{account_id}/{type}
	- 계정의 meta, struct, name, key 데이터와 해시값 가져오기
	- 없다면 타 노드로 중계하여 반환
	- 응답: 200 OK {data: bytes, hash: bytes}, 404 Not Found
- POST /account/{account_id}/{type}
	- 쓰기 권한 확인하고 계정 구성요소 저장, 덮어쓰기
	- 처음에 보내준 해시값이 덮어써질 데이터와 일치해야 함
	- 쿼리: spread: bool
	- 요청: {hmac-set, data: bytes, prevHash: bytes, newHash: bytes}
	- 응답: 200 OK, 401 Unauthorized, 404 Not Found, 409 Conflict

### 상태 관련
	
- GET /status
	- 서버 동작 여부 체크
	- 응답: 200 OK {nodeId: string, connected: string[], storeLimit: int, storeUsed: int}
- GET /status/detail
	- 관리자 권한으로 서버 세부상태 조회
	- 요청: {hmac-set}
	- 응답: 200 OK, {vaults: string[], accounts: string[][]}
- POST /system/trim/{vault_id}
	- 쓰기 권한 확인하고 유휴 시간에 저장소 청크 정리
	- 블룸 필터가 유효한 청크는 남기고 고아 청크는 확률적으로 삭제
	- 쿼리: spread: bool
	- 요청: {hmac-set, filter: bytes, hashCount: int}
	- 응답: 202 Accepted, 401 Unauthorized, 404 Not Found
- POST /system/check/{vault_id}
	- 쓰기 권한 확인하고 해당 저장소의 청크가 있는지 반환
	- 비트 불리언 사용하여 공간 절약
	- 요청: {hmac-set, chunks: bytes[]}
	- 반환: 200 OK {exist: bytes[]}, 401 Unauthorized, 404 Not Found

### 무결성 유지
	
- 파일명은 base64(chunk_id 16B + hash 32B)로 설정
- 한가할 때 무작위 청크의 해시값 읽고 검증
- 청크 반출 시 검사
- 해시가 불일치한다면 다른 노드에 요청

## 클라이언트

- 클라이언트는 노드 하나를 골라 입출력 창구로 사용
- 물리 장치로 연결된 로컬 저장소인 경우 클라이언트가 직접 쓰기도 가능
- 모든 암호화 로직과 폴더 트리 재구성은 클라이언트 담당
- 파일을 일정 단위로 잘라 청크화, [저장소 ID 6B][파일 UID 6B][청크 순서 4B]를 암호화해 16B를 청크 ID로 사용
- 사용패턴 보호를 위해 자동으로 더미 파일을 생성 삭제
