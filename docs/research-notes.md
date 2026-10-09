# SentinelEKS — 리서치 노트 (기획서 검증 결과)

작성: 2026-10-09 11:46 PDT · 마감 **4:30 PM PT** (남은 시간 약 4h40m)
근거: 스폰서 공식 문서, tokensand.com/cyberhack, luma.com/cyberhack, ATDR 레포(`ninejuan/eks-ai-threat-detection-and-response` @ `1dead7e`) 직접 확인.
표기: ✅ 확인 · ❌ 기획서와 다름 · ⚠️ 미확인/현장 확인 필요

---

## 0. 기획을 바꾸는 핵심 발견 7가지

1. ❌ **Pi는 이번 행사에서 제품·기술 접근을 제공하지 않음** (tokensand 원문: "Product and tech access are not being provided at this event"). Pi는 **종합 순위(Top overall) 상금 스폰서**. `app/gate/pi_review.py`(M11)는 **삭제**. Pi 심사위원 2명(Mike Caballero, Rishiraj Chandra)이 종합 심사를 하니 완성도·아이디어에 집중.
2. ✅ **Semgrep 상금 기준 = "AI가 생성한 코드에서 Semgrep이 찾은 최고의 취약점"** ($1,000/$500 현금). 우리 게이트(AI가 만든 대응 매니페스트를 Semgrep으로 스캔)와 정확히 맞음. 데모에서 **LLM이 위험한 매니페스트를 만들고 → Semgrep이 잡고 → 차단**하는 장면이 반드시 있어야 함 (통과만 보여주면 상금 기준을 못 맞춤).
3. ✅ **Guild.ai 상금이 실재** (1위 $1,000 + 2·3위 $500, 심사위원 Corbett Waddingham). API 트리거(인증된 HTTP 호출로 에이전트 실행)가 있어서 Lambda에서 호출 가능. "선택 확장"에서 **2순위 확장**으로 올림 (§3 Guild 참조).
4. ✅ **ClickHouse 심사 기준 = 데이터 규모, 쿼리/응답 지연, 인사이트가 탐지·대응·모니터링을 얼마나 직접 움직이는가.** 상관 승격(P3→P1)이 정확히 "인사이트가 대응을 움직이는" 사례. 데모에 **쿼리 지연(ms)과 적재 건수**를 숫자로 보여줄 것.
5. ❌ **레포에 공격 시뮬레이션 스크립트가 없음.** `docs/08-attack-simulation.md`에 YAML/bash 블록이 있는 설계 문서일 뿐이고 `apps/attack-simulator/`는 없음. 크립토마이닝 시뮬은 **직접 작성**해야 함 (문서 블록을 `scripts/sim-cryptomining.sh`로 옮기기, 30분 이하 예상).
6. ❌ **MCP 도구 이름이 기획서의 화이트리스트와 다름.** 실제 도구 목록은 §2 참조. 화이트리스트를 실제 이름에 맞춰 다시 정의해야 함.
7. ❌ **Senso 응답에는 `citations` 필드가 없음.** `results[]`(content_id, title, chunk_text, score, rank)가 곧 인용이므로 content_id 기준으로 중복을 제거해 citations를 직접 만들어야 함.

상금이 걸린 스폰서는 ClickHouse, Pi(종합), Akash, Guild, Semgrep, Senso 6곳. OpenAI·MongoDB·ElevenLabs·Induction Labs는 tokensand 상금 표에 없음(파트너 로고만, ⚠️ 현장 공지 확인). MongoDB는 상금은 없어도 Tool Use 3개+ 카운트와 아키텍처 측면에서 유지할 가치가 있음.

---

## 1. 행사 사실 (tokensand / luma)

| 항목 | 내용 |
| --- | --- |
| 일정 (PT) | 11:00 킥오프 · 1:30 점심 · **4:30 제출 마감** · 5:00 결선 데모 · 7:00 시상 |
| 장소 | AWS Builder Loft, SF |
| 제출 항목 | ① 심사위원이 접근 가능한 **GitHub 레포** ② **데모 영상 공유 링크** (3분) ③ 만든 것과 사용 도구 ④ 팀원 이름·이메일. 웹사이트·스크린샷은 선택 |
| 스폰서상 | 제출 폼에서 상마다 **개별 선택**해야 함 |
| 심사위원 | Pi 2명, OpenAI, Guild, AWS, Akash(Greg Osuri), ClickHouse, Semgrep(Daghan Altas), Airbyte, FlowiseAI, Visibl |

| 스폰서 | 상금 | 기준 |
| --- | --- | --- |
| ClickHouse | $1,000+$500 크레딧 / $500+$300 / $250 | 데이터 규모, 지연, 인사이트→탐지/대응 직결성 |
| Pi | 종합 $1,000 / $600 / $400 | 종합 (Pi 기술 접근 없음) |
| Akash | $500 / $250 / $150 크레딧 | AkashML 추론 활용 |
| Guild.ai | $1,000 / $500 / $500 | Guild로 에이전트 호스팅·실행 |
| Semgrep | $1,000 / $500 현금 + 크레딧 | AI 생성 코드에서 Semgrep이 찾은 최고의 취약점 |
| Senso | 3k / 1k / 1k 크레딧 | Senso(검증 컨텍스트 레이어) 활용 |

---

## 2. ATDR 레포 실제 구조 (기획서 가정 대조)

| 기획서 가정 | 판정 | 실제 |
| --- | --- | --- |
| `app/agents/{summary,triage,solution,remediation}/` | ✅ + 1 | **`forensic_synthesis/`가 5번째로 있음** (Remediation 다음에 실행되며 인용 포함 포렌식 리포트 생성) |
| `app/shared/`에 Bedrock 모듈 | ✅ | `app/shared/bedrock.py` `BedrockClient.invoke()` / `invoke_with_tools()` |
| Bedrock 모델 Claude 3.5 Haiku/Sonnet | ❌ | FAST: `global.anthropic.claude-haiku-4-5-20251001-v1:0`, SMART: `global.anthropic.claude-sonnet-4-5-20250929-v1:0` (폴백 체인 있음). 함수별 env `BEDROCK_MODEL_ID` |
| 리전 us-west-2 | ❌ | 레포 기본값 **ap-northeast-2**. AWS 학교 계정 리전과 Bedrock 모델 활성화 여부 확인 필요 |
| Step Functions가 DynamoDB를 직접 호출? | ❌ (좋은 소식) | 모든 상태가 `lambda:invoke` 또는 `waitForTaskToken`. DynamoDB 접근은 전부 Lambda 내부라 **Mongo 교체 시 ASL 수정 불필요** |
| DynamoDB 테이블 | ✅ + 2 | `incidents`, `approval-audit`, **`event-dedup`**, **`tetragon-events`** (`terraform/envs/demo/main.tf`) |
| 조건부 쓰기 존재 | ❌ 부분 | `ConditionExpression`은 ingestor dedup(`app/ingestor/handler.py:145`)에만 있음. **incidents·승인 쪽에는 없음** → M7에서 새로 추가 |
| Slack 승인 멱등성 | ❌ | `app/slack_bot/interactions.py:_process_approval`이 그냥 `put_item` 후 `send_task_success`. 앱 레벨 dedup 없음 (SFN이 두 번째 task token 완료를 거부하는 것뿐) |
| Slack 봇 프레임워크 | — | Bolt가 아니라 순수 Lambda + Block Kit. 버튼 value = `incident_id\|task_token` |
| OpenSearch RAG | ✅ | Bedrock Knowledge Base(Titan v2 임베딩) + OpenSearch Serverless. `app/shared/knowledge_base.py` `KnowledgeBaseClient.retrieve()` |
| 런북 | ✅ | `docs/11-runbooks/` 10개 (cryptomining, container-escape, data-exfiltration, dns-anomaly, image-tampering, lateral-movement, privilege-escalation, rbac-abuse, reverse-shell, secret-exfiltration). **Senso ingest 소스로 그대로 사용** |
| 공격 시뮬 스크립트 | ❌ | 없음. `docs/08-attack-simulation.md` 문서 블록뿐 |
| `make infra-up` 15~20분 | ✅ | README 기준. `platform-up`이 추가로 10~15분 |
| Python | ✅ | 3.12, `make build-layer`, ruff/yamllint/pytest CI |

SFN 흐름 (`terraform/modules/lambda/main.tf:224-480`):
`Summary → Triage → CheckSeverity (P4→LogOnly / P3→Solution→Remediation / P1·P2→SolutionWithApproval→WaitForApproval(taskToken)→CheckApproval) → ForensicSynthesis → End`, 오류는 전부 `DegradedNotify`로 Catch. ResultPath는 `$.summary`, `$.triage`, `$.solution`, `$.approval`, `$.remediation`, `$.forensic_synthesis`.

**MCP 실제 도구** (`mcp_server/server.py`, 클러스터 내부, `MCP_AUTH_TOKEN` Bearer):
`label_pod`, `delete_pod`, `apply_cilium_network_policy`, `patch_deployment`, `cordon_node`, `drain_node`, `checkpoint_pod`, `capture_hubble_flows`, `collect_tetragon_timeline`, `collect_audit_events`, `collect_live_pod_forensics`, `checkpoint_container_experimental`

**수정한 액션 화이트리스트** (기획서 이름 → 실제 도구):

| 기획서 | 실제 도구 |
| --- | --- |
| `forensic_snapshot` (파괴 전 필수) | `checkpoint_pod` (+ 선택 `collect_live_pod_forensics`) |
| `isolate_pod` | `label_pod`(quarantine 라벨) + `apply_cilium_network_policy` |
| `apply_networkpolicy(deny-all)` | `apply_cilium_network_policy` |
| `sigkill_label` | 별도 도구 없음. Tetragon SIGKILL은 TracingPolicy + 라벨 방식 → `label_pod`로 대체, 또는 `delete_pod`(grace 0) |
| `scale_deployment(0)` | `patch_deployment` (replicas=0) |

`cordon_node`·`drain_node`는 블라스트 반경이 크므로 데모 화이트리스트에서 **제외**.

---

## 3. 스폰서별 검증된 연동 정보

### Senso ✅ (상금 있음, 핵심 축)
- Base `https://apiv2.senso.ai/api/v1`, 헤더 **`X-API-Key: tgr_...`** (REST는 Bearer 아님)
- Ingest: `POST /org/kb/raw {title, text, kb_folder_node_id?}` → 202 `{id: content_id, kb_node_id, processing_status}`. 같은 텍스트를 다시 넣으면 **409 → 이미 있는 것으로 처리**. 마크다운은 파일 업로드가 아니라 raw로 넣어야 함
- 상태 폴링: `GET /org/kb/nodes/{kb_node_id}` → `content.processing_status` ∈ pending/processing/complete/failed
- 검색: `POST /org/search {query, max_results≤20, content_ids?, require_scoped_ids?}` → `{answer, results:[{content_id,title,chunk_text,score,rank}], total_results}`
  - `/org/search/context`(raw chunk), `/org/search/content`(ID·제목만), `/org/search/full`
- **인용 검증 (verify.py)**: ingest할 때 받은 content_id 집합을 런북 매니페스트(`data/senso_manifest.json`)로 저장해 두고, solution.citations의 content_id가 그 집합 안에 있는지 확인. 또는 `require_scoped_ids=true` + `content_ids=[런북 ID들]`로 검색 범위 자체를 검증된 런북으로 묶음 → **"truthful sources" 메시지가 가장 강해지는 방법**
- 고급 옵션(시간 남으면): Evals `kb_accuracy`로 생성된 대응문의 주장별 verified/conflict/unsupported 판정 (REST 경로 ⚠️ 미확인)
- MCP `https://apiv2.senso.ai/mcp`도 있지만 백엔드에서는 REST가 적합
- 크레딧 소비형. `GET /org/credits/balance`, 402 = 크레딧 소진

### AkashML ✅ (상금 있음)
- `https://api.akashml.com/v1`, `Authorization: Bearer`, OpenAI SDK에서 `base_url`만 교체. 키는 akashml.com → Settings → API Keys
- 모델 ID: `meta-llama/Llama-3.3-70B-Instruct` ✅. 그 외 `openai/gpt-oss-120b`, `Qwen/Qwen3.6-35B-A3B`, `moonshotai/Kimi-K3`, `zai-org/GLM-5.3` 등. **DeepSeek V3는 현재 카탈로그에 없음** → 착수 전 `GET /v1/models`로 확인
- `tools`, `tool_choice`, `response_format: json_schema` 지원 → Solution 출력을 JSON 스키마로 강제할 수 있음
- 오류: 429, 402(크레딧), 504/529(백엔드 없음) → Bedrock 폴백 트리거
- 크레딧 $100은 ⚠️ 블로그 기준

### ClickHouse ✅ (상금 있음)
- Cloud 체험판 ($300 / 30일, ⚠️ 3rd-party 출처). HTTPS 8443
- `clickhouse_connect.get_client(host, port=8443, secure=True, username, password)`
- 서버 측 바인딩 `{name:Type}` + `client.query(sql, parameters={...})` ✅
- `client.insert(table, rows, column_names=[...])`: column_names를 명시해야 타입 조회 왕복이 생략됨
- IP Access List에 NAT EIP /32 추가 (기본값은 "anywhere")
- 데모 강화: 배경 노이즈 이벤트 수만 건을 미리 시드(데이터 규모) + Q1/Q2 응답의 `elapsed`/`rows_read`를 Slack 카드와 Canvas에 표시(지연)

### MongoDB Atlas ✅ (상금 없음, 상태 저장소)
- M0: 0.5GB, 연결 500개, 프로젝트당 1개. `pymongo[srv]`(dnspython) 필요
- 클라이언트는 전역에서 생성, `serverSelectionTimeoutMS=5000`
- IP Access List에 NAT EIP 추가
- 멱등 전이: `update_one({"_id": iid, "status": "awaiting_approval"}, {"$set": ...})` → `modified_count == 0`이면 중복으로 보고 무시. **이 경우 `send_task_success`도 호출하지 않음** (레포의 멱등성 공백을 메움)
- `approval_audit`은 `{incident_id, slack_message_ts, decision}`에 유니크 인덱스를 걸어 Slack 재전송 시 중복 insert를 DB 차원에서 차단

### Semgrep ✅ (상금 있음, 데모 장면 필수)
- `semgrep scan --config p/kubernetes --config rules/ --json manifest.yaml` → `{results[], errors[], paths}`, `extra.severity` ∈ ERROR/WARNING/INFO
- **Lambda 레이어 불가**: 패키지만 110~164MB, 전체 이미지 345~427MB vs 레이어 한도 250MB → **컨테이너 이미지 Lambda**(`returntocorp/semgrep` 기반) 또는 대안 (§4)
- `p/kubernetes` 규칙 내용은 ⚠️ 미확인 → 착수 시 로컬에서 `semgrep --config p/kubernetes`를 샘플 매니페스트에 돌려 실제로 무엇을 잡는지 확인
- 커스텀 규칙(`rules/sentinel-remediation.yaml`, `semgrep --validate`/`--test`로 검증):
  - 보호 네임스페이스(kube-system 등) 대상 정책 금지
  - `endpointSelector: {}` / `podSelector: {}`(네임스페이스 전체 차단) 금지 → AI가 단일 파드가 아닌 전체를 격리하려는 실수
  - egress `toEntities: [world]` / `0.0.0.0/0` 허용 금지 (격리라면서 열어두는 실수)
  - `privileged: true`, `hostPID`, `hostNetwork` 포함 시 금지 (포렌식 파드 생성 시)
- 상금 데모 시나리오: Remediation LLM이 첫 시도에서 **네임스페이스 전체 `endpointSelector: {}` deny-all**을 생성(현실적으로 자주 나오는 실수)하면 Semgrep이 ERROR로 잡고, 모델에 피드백해 재생성하면 단일 파드 셀렉터로 통과. "AI 생성 코드의 취약점 발견"이 영상에 그대로 남음
- 참고: `claude plugin install semgrep@claude-plugins-official` (스폰서 안내)

### Slack ✅
- 3초 ack는 필수. 레포 구조(Lambda URL/API GW)를 유지하되 무거운 작업은 비동기로
- Canvas: `canvases.create {title, document_content:{type:"markdown", markdown}}` → canvas_id; `canvases.edit {canvas_id, changes:[{operation:"insert_at_end"|"replace", document_content}]}` (호출당 operation 1개); 채널 탭은 `conversations.canvases.create`. 스코프 `canvases:write`
- ⚠️ 무료 워크스페이스에서 API로 Canvas 생성 가능 여부 미확인 → 착수 직후 한 번 호출해 보고, 안 되면 스레드 메시지로 폴백

### Guild.ai ✅ (상금 있음, 재평가)
- CLI `@guildai/cli`, SDK `@guildai/agents-sdk`(TypeScript). LangGraph 타입(`graph.py`)으로 Python도 가능
- `guild agent init --template LLM` → `guild agent test --ephemeral` → `guild agent save --message ... --wait --publish`. 간단한 에이전트는 수분 내 배포 가능
- 트리거: Slack/GitHub 웹훅, 스케줄, **API 트리거(인증된 HTTP)**
- 크리덴셜 프록시(에이전트가 원본 키를 못 봄) + 감사 로그(User actions / Security events)
- 기획서의 "실행 모델 충돌" 판단은 맞음 (체인 전체를 옮기면 안 됨). 다만 독립 조각 하나는 의미 있게 올릴 수 있음:
  - **안 A (추천): "Incident Commander" Guild 에이전트.** SFN 종료 후(또는 Slack `@sentinel` 멘션 시) API/Slack 트리거로 실행. MongoDB 인시던트 문서를 읽어 Canvas 상태 페이지를 쓰고 갱신하는 **publish 역할**을 Guild가 맡음. Slack 크리덴셜은 Guild 프록시가 주입하고 Guild 감사 로그에 남음 → "자율 에이전트가 정책·감사 아래 웹에 게시"
  - 안 B: Slack 멘션 트리거로 인시던트 질의응답 에이전트 (상금 기준엔 맞지만 데모 경로에서 벗어남)
- 비용: 45~60분 (TS 작성 + 인증 + 트리거 연결). M12(게시)와 합치면 중복 작업이 줄어듦

### Pi ❌ — 제외 (§0-1)
### Induction Labs ❌ — 제외 (공개 API 없음, 상금 없음. induction.ai는 다른 회사)
### OpenAI / ElevenLabs ❌ — 상금 기준 없음, 제외

---

## 4. 수정 아키텍처 제안 (delta)

1. **Pi 게이트 삭제** → 게이트는 `Semgrep → verify.py` 2단. Semgrep에 "실패 시 1회 재생성" 루프 추가 (상금 데모 포인트)
2. **Semgrep 실행 위치**: 우선순위
   - (a) 컨테이너 이미지 Lambda `semgrep-gate` (ECR push + SFN Task 추가, 이미지 빌드·푸시에 약 30분)
   - (b) 시간이 부족하면 **EKS 안의 MCP 서버 파드에 semgrep 설치** 후 `scan_manifest` 도구 추가 → Remediation이 MCP로 호출 (인프라 변경 최소)
   - (c) 최후 수단: 로컬 오케스트레이터에서 subprocess
3. **화이트리스트**를 실제 MCP 도구명으로 재정의 (§2)
4. **SFN**: ASL에 상태 추가가 필요한 곳은 `SemgrepGate`(Remediation 다음)뿐. 기존 Choice/Wait 구조 유지. ForensicSynthesis는 그대로 두고 Senso 인용으로 교체 가능 (선택)
5. **게시(publish)**: Canvas가 "open web에 실제 행동"의 핵심 증거. Guild 안 A로 감싸면 Guild 상금까지 커버
6. **공격 시뮬**: `scripts/sim-cryptomining.sh` 신규 작성 (xmrig 흉내 프로세스 + 마이닝 풀 포트 egress) → Falco와 Tetragon이 동시에 발화해 ClickHouse 상관 승격 조건(센서 2개+)을 확실히 만족시키도록 설계

## 5. 리스크와 시간 예산 (현재 11:46, 마감 16:30)

| 리스크 | 영향 | 대응 |
| --- | --- | --- |
| 인프라가 아직 안 떠 있음 | `infra-up` + `platform-up` = 25~35분 | **지금 바로 백그라운드로 시작** (가장 긴 크리티컬 패스) |
| Bedrock 모델 접근 (학교 계정·리전) | 체인 전체 중단 | 첫 15분 안에 `invoke_model` 스모크 테스트. 안 되면 리전 변경 또는 Akash로 전체 폴백 |
| 키 발급 (Senso / Akash / ClickHouse / Atlas) | 각 5~10분 | 병렬로 가입. 사람(팀원)이 해야 하는 작업 |
| Semgrep 패키징 | 30분 | 안 (b)로 리스크 회피 가능 |
| Slack Canvas 무료 플랜 | 게시 장면 | 즉시 API 호출로 확인, 폴백은 스레드 |
| 3분 영상 촬영·업로드 | 마감 직전 병목 | **15:45에 기능 동결**, 16:00까지 녹화, 16:15 제출 |

제안 타임라인:
- 11:50–12:10: 인프라 기동 시작 + 키 발급 + Bedrock/Akash/Senso 스모크 (M1·M2)
- 12:10–13:30: llm 라우터, senso.py, Solution/Triage 교체, ClickHouse 싱크 (M3·M4·M6)
- 13:30–14:30: Mongo 교체 + 멱등 승인, verify.py, 공격 시뮬 스크립트 (M5·M7·M8)
- 14:30–15:15: Semgrep 게이트 + 재생성 루프, Canvas 게시 (M10·M12)
- 15:15–15:45: 엔드투엔드 리허설 (M9·M13), 시간이 남으면 Guild
- 15:45–16:15: 녹화·README·제출 (스폰서상 6개 체크: ClickHouse, Pi(종합), Akash, Guild(했다면), Semgrep, Senso)

## 5.5 로컬 환경 확인 결과 (11:55)
- ATDR 코드(`1dead7e`)를 이 레포 루트로 복사함. 원본 README는 `docs/ATDR-README.md`로 보관
- AWS: account 156041424727, `ap-northeast-2`. tfstate 버킷 `atdr-tfstate`는 있음(state는 비어 있음). **EKS 클러스터 없음** → `make infra-up` 필요
- Bedrock: `global.anthropic.claude-haiku-4-5-20251001-v1:0` invoke 성공. 레포 기본 모델 ID를 그대로 쓰면 됨
- ⚠️ 셸에 만료된 `AWS_BEARER_TOKEN_BEDROCK`이 있어 Bedrock 호출을 가로챔 → 로컬 테스트할 때 `unset AWS_BEARER_TOKEN_BEDROCK` (Lambda에는 영향 없음)
- ⚠️ Docker daemon이 꺼져 있음 → `make platform-up`(MCP 이미지 빌드) 전에 켜야 함
- semgrep CLI는 로컬에 설치돼 있음. Semgrep Cloud 토큰(`SEMGREP_APP_TOKEN`)을 받으면 결과를 Cloud 대시보드에도 올릴 수 있음
- Pi: 사용자 확인으로 **최종 제외**

## 5.6 크레덴셜 스모크 테스트 (12:55, `.credentials`, read-only)
| 서비스 | 결과 | 비고 |
| --- | --- | --- |
| Senso | ✅ `/org/me` 200 | org `sftwcyberdefhack26@juany.dev`, free tier |
| AkashML | ✅ `/v1/models` 200 | `meta-llama/Llama-3.3-70B-Instruct`, `openai/gpt-oss-120b`, `Qwen/Qwen3.6-35B-A3B`, `Qwen/Qwen3.8-27B`, `zai-org/GLM-5.3`, `moonshotai/Kimi-K3`, `openai/gpt-oss-20b` |
| Slack | ✅ `auth.test` ok | 워크스페이스 Sigmoid Corporation, bot `sentineleks`. **토큰 scope가 `incoming-webhook` 하나뿐** → manifest의 bot scope를 적용하고 재설치해야 함 |
| MongoDB Atlas | ✅ ping | DB 비어 있음. 현재 IP에서 접근 가능 |
| ClickHouse Cloud | ✅ 26.6.1 | `wlu0eizn2e.us-east-1.aws.clickhouse.cloud:8443` (us-east-1, Lambda는 ap-northeast-2라 RTT 약 150ms) |
| Semgrep | ✅ `semgrep ci` 인증 통과 | deployment `juanylab`, Pro rules 1869 + Community 1075. Web API(`/api/v1/*`)는 404 = 무료 티어라 미지원(예상대로). **findings 업로드에는 git remote(`SEMGREP_REPO_URL`)가 필요** |

## 5.7 리전 이전: us-east-1 (13:05)
- 사용자 결정에 따라 배포 리전을 `us-east-1`로 변경. Bedrock `global.*` Haiku 4.5 / Sonnet 4.5 invoke 성공 확인. ClickHouse Cloud와 같은 리전이라 RTT도 줄어듦
- 수정한 곳: `terraform/envs/demo/variable.tf`(region 기본값), `main.tf`(AZ를 `${var.region}a/b`로), `modules/vpc/variables.tf`, `modules/kms`(ViaService에 `var.region` 사용, region 변수 추가), `Makefile`·`init.sh` 폴백값, `app/shared/{config,bedrock,knowledge_base}.py` 기본값과 `apac.*` 폴백 모델 → `us.*`, `scripts/create_opensearch_index.py`, `kubernetes/falco/values*.yaml`, `kubernetes/tetragon/sns-forwarder.yaml`, `tests/shared/test_config.py`
- **tfstate backend는 `ap-northeast-2` 버킷 `atdr-tfstate`를 유지** (state 위치와 배포 리전은 서로 무관. state는 비어 있음)
- `terraform validate` 통과. pytest 118 passed, 6 errors는 로컬에서 hubble proto 스텁(`flow` 모듈, Dockerfile에서 생성)이 없어서 생긴 것이고 코드 문제가 아님
- Slack 재설치 후 scope 확인: `chat:write`, `chat:write.public`, `canvases:write/read`, `channels:read` 등 12개 정상
- GitHub: `ninejuan/sentineleks-cyberhack26` (public, origin 설정됨, main에 README 커밋 1개)

## 5.8 모델 교체와 이름 변경 (13:30)
- **LLM: OpenAI GPT-5.6을 Bedrock으로 호출** (OpenAI 키 없이 기존 IAM 경로 사용). us-east-1에서 `us.openai.gpt-5.6-{luna,terra,sol}` 모두 Converse와 tool-use로 동작 확인
  - Summary·Triage → **Luna** (가장 저렴, 1초 내외)
  - Solution·Remediation·ForensicSynthesis → **Terra** (지연 0.6~1초, tool-use 정확, Sol 대비 비용 약 절반)
  - Sol을 뺀 이유: Terra로 실제 remediation 루프를 돌렸을 때 checkpoint_pod → capture_hubble_flows → label_pod 순서를 그대로 지켰음. Sol은 비용 2배·지연 2배에 데모상 이득이 없음
  - `app/shared/bedrock.py`를 `invoke_model`(Anthropic 포맷)에서 **Converse API**로 교체. 에이전트 쪽 계약({stop_reason, content:[{type...}]})은 유지해서 handler는 수정 없음
- AkashML(Llama 3.3 70B)은 Solution 단계 라우팅으로 별도 추가 예정 (Akash 상금)
- **프로젝트 이름 `atdr` → `seks`**: 코드·인프라·매니페스트·테스트·문서 전부 변경. tfstate 버킷은 `seks-tfstate`(us-east-1)이고 **아직 없음** → `./init.sh` 실행 필요
- 커밋: `Import ATDR base` → `Move region to us-east-1` → `Add Slack canvas scopes` → `Add hackathon notes` → `Use GPT-5.6 on Bedrock` → `Rename project to seks`
- 기존 ruff 오류 11건(PLR0917, ISC004)은 ATDR 원본에도 있던 것이고 이번 변경과 무관

## 6. 현장에서 확인할 것
- [ ] AWS 계정 리전과 Bedrock Claude 4.5 모델 활성화 여부
- [ ] Slack 워크스페이스 플랜 (Canvas API)
- [ ] OpenAI·MongoDB·ElevenLabs 별도 상금 유무 (Andy, 프런트 데스크)
- [ ] Akash 크레딧 지급 방식 (부스)
- [ ] Senso 해커톤 크레딧
- [ ] 제출 시 레포 public 필요 여부 ("reviewers can access")
