# agent-comply

**AIエージェントワークフローのための改ざん防止コンプライアンス監査**

AIエージェントが行うすべての意思決定をキャプチャし、改ざんがないことを証明し、あらゆる出力の因果チェーンを再構築し、関連する規制フレームワークにマッピングします。

---

## 課題

AIエージェントは規制産業（医療、金融、保険、法務）で重大な意思決定を行っています。規制当局は説明可能性、監査可能性、コンプライアンスの証明を求めています。従来のログでは不十分です。ログは改ざん可能で、因果チェーンは不可視で、エージェントの行動を特定の規制コントロールにマッピングするには、スケールしない手作業が必要です。

**agent-comply**は、暗号学的に検証可能な監査証跡に組み込みの意思決定再構築と自動化された規制コンプライアンスマッピングを提供することで、この問題を解決します。

## 主な特徴

- **改ざん防止台帳** — SHA-256ハッシュチェーニングとMerkleツリー整合性検証を備えたappend-onlyイベントストア。過去のイベントへのいかなる変更も暗号学的に検出可能
- **因果的意思決定再構築** — イベント依存関係（時間的、データフロー、ツール呼び出しエッジ）の有向非巡回グラフ（DAG）を自動構築し、あらゆるエージェント出力の完全な因果チェーンを抽出。反事実What-If分析も対応
- **マルチフレームワークコンプライアンスマッピング** — 5つの規制フレームワークと16のコントロールに対してエージェント監査証跡を評価し、コントロールごとのエビデンス、所見、推奨事項を含む構造化レポートを生成
- **行動異常検出** — エージェントごとのベースラインを構築し、6つの検出ルール（異常なセッション長、高エラー率、未知のツール、過剰なデータアクセス、低速な呼び出し、ポリシー違反）でzスコア分析によりセッションをスコアリング
- **ゼロオーバーヘッドキャプチャSDK** — `@audit`デコレータ一つで、同期・非同期関数の入力、出力、エラー、タイミングを透過的にキャプチャ
- **エビデンスパッケージング** — ワンコマンドで監査人向けの完全なエビデンスパッケージ（イベント、コンプライアンスレポート、タイムライン、異常レポート、整合性証明）をエクスポート

## アーキテクチャ

```
                         ┌──────────────────────────────────────┐
                         │           Your AI Agent Code         │
                         │                                      │
                         │   @audit                             │
                         │   def search(query): ...             │
                         │                                      │
                         └──────────────┬───────────────────────┘
                                        │  captures events
                                        ▼
┌───────────────────────────────────────────────────────────────────┐
│                        agent-comply                               │
│                                                                   │
│  ┌─────────────┐   ┌──────────────┐   ┌───────────────────────┐  │
│  │   Capture    │──▶│   Ledger     │──▶│   Merkle Tree         │  │
│  │   SDK        │   │  (append-    │   │   (O(log n) proofs)   │  │
│  │  (@audit)    │   │   only,      │   │                       │  │
│  │              │   │   hash-      │   └───────────────────────┘  │
│  └─────────────┘   │   chained)   │                              │
│                     └──────┬───────┘                              │
│                            │                                      │
│            ┌───────────────┼───────────────┐                     │
│            ▼               ▼               ▼                     │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐             │
│  │ Reconstruct  │ │  Compliance  │ │   Anomaly    │             │
│  │  (DAG-based  │ │   Mapper     │ │  Detector    │             │
│  │   causal     │ │ (5 frameworks│ │ (z-score     │             │
│  │   chains,    │ │  16 controls)│ │  baselines)  │             │
│  │   counter-   │ │              │ │              │             │
│  │   factuals)  │ │              │ │              │             │
│  └──────┬───────┘ └──────┬───────┘ └──────┬───────┘             │
│         └────────────────┼────────────────┘                     │
│                          ▼                                       │
│                 ┌──────────────┐                                 │
│                 │   Reporter   │                                 │
│                 │  (text, JSON,│                                 │
│                 │   evidence   │                                 │
│                 │   packages)  │                                 │
│                 └──────────────┘                                 │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
                                │
                                ▼
                         ┌──────────────┐
                         │     CLI      │
                         │  agent-comply│
                         └──────────────┘
```

## クイックスタート

### インストール

```bash
pip install agent-comply
```

ソースからインストールする場合：

```bash
git clone https://github.com/mattyopon/agent-comply.git
cd agent-comply
pip install -e ".[dev]"
```

### エージェントの計装

```python
from agent_comply import audit, AuditContext

@audit
def search_database(query: str) -> list[str]:
    """既存のエージェントツール — 内部の変更は不要です。"""
    return ["result_1", "result_2"]

@audit(event_type="tool_call", metadata={"tool": "web_search"})
async def web_search(url: str) -> str:
    """非同期関数にも対応しています。"""
    return "<html>...</html>"

# 監査コンテキスト内で実行
with AuditContext(agent_id="claims-agent") as ctx:
    results = search_database("patient records")
    # すべての呼び出しが改ざん防止台帳にキャプチャされます

    # 検証用にエクスポート
    ctx.ledger.export_jsonl("events.jsonl")
```

### 検証とレポート

```bash
# 台帳の整合性を検証
agent-comply verify events.jsonl

# コンプライアンスレポートを生成
agent-comply report events.jsonl --framework eu-ai-act

# 異常を検出
agent-comply anomaly events.jsonl

# 意思決定チェーンを再構築
agent-comply reconstruct events.jsonl --event-id EVT-abc123def456

# 完全なエビデンスパッケージをエクスポート
agent-comply evidence events.jsonl --output-dir evidence-package/
```

## CLIリファレンス

| コマンド | 説明 | 主要オプション |
|---------|------|---------------|
| `verify` | 台帳の整合性を検証（ハッシュチェーン＋Merkleツリー） | `EVENTS_FILE` |
| `reconstruct` | 特定のイベントの因果チェーンを再構築 | `--event-id`, `--output` |
| `report` | コンプライアンスレポートを生成 | `--framework`（eu-ai-act, soc2, hipaa, gdpr, dora, all）、`--format`（text, json）、`--output` |
| `anomaly` | エージェントセッションの行動異常を検出 | `--output` |
| `evidence` | 監査人向けの完全なエビデンスパッケージをエクスポート | `--output-dir` |
| `info` | 台帳ファイルの概要情報を表示 | `EVENTS_FILE` |

## サポートする規制フレームワーク

| フレームワーク | コントロール数 | 対象 |
|-------------|-------------|------|
| **EU AI Act** | 4 | 意思決定の透明性（第13条）、人間の監視（第14条）、自動ログ記録（第12条）、リスク分類（第6条） |
| **SOC 2** | 3 | 監査証跡の完全性（CC7.2）、整合性（CC7.3）、保持（CC7.4） |
| **HIPAA** | 3 | ePHIアクセス監査（164.312b）、整合性（164.312c1）、エンティティ認証（164.312d） |
| **GDPR** | 2 | 処理活動の記録（第30条）、説明を受ける権利（第22条） |
| **DORA** | 3 | ICTインシデントログ記録（第11条）、レジリエンステスト（第25条）、第三者リスク（第28条） |

## SDK使用方法

### `@audit`デコレータ

デコレータは関数ロジックを一切変更せずに、入力、出力、エラー、実行時間をキャプチャします：

```python
from agent_comply import audit, AuditContext, EventLedger

# 基本的な使い方 — すべて自動的にキャプチャ
@audit
def classify_risk(document: str) -> str:
    return "high"

# メタデータとイベントタイプのカスタマイズ
@audit(event_type="tool_call", metadata={"tool": "llm", "model": "gpt-4"})
def call_llm(prompt: str) -> str:
    return "LLM response"

# 非同期サポート
@audit
async def fetch_records(patient_id: str) -> dict:
    return {"id": patient_id, "records": [...]}
```

### プログラムによるコンプライアンスチェック

```python
from agent_comply import EventLedger, ComplianceMapper, DecisionReconstructor, AnomalyDetector

# 台帳の読み込みと検証
ledger = EventLedger.import_jsonl("events.jsonl")
ok, errors = ledger.verify_all()
assert ok, f"Ledger tampered: {errors}"

# コンプライアンス評価
mapper = ComplianceMapper(ledger)
report = mapper.evaluate(Framework.HIPAA)
print(f"HIPAA score: {report.score}%")

# 意思決定の再構築
recon = DecisionReconstructor(ledger)
chain = recon.get_causal_chain("EVT-target123")
print(f"Causal depth: {chain.depth}, events in chain: {len(chain.chain)}")

# 反事実分析
result = recon.counterfactual("EVT-abc123", "output", "alternative_value")
print(f"Impact score: {result.impact_score}, affected: {len(result.affected_events)} events")

# 異常検出
detector = AnomalyDetector(z_threshold=2.0)
detector.train(ledger)
session_reports = detector.analyse(ledger)
for sr in session_reports:
    if sr.risk_score > 0.5:
        print(f"HIGH RISK session {sr.session_id}: {sr.risk_score}")
```

## 仕組み

### ハッシュチェーン整合性

台帳内のすべてのイベントは、その内容のSHA-256ハッシュと前のイベントのハッシュへの参照を保存し、切れることのないチェーンを形成します。過去のイベントを変更するとそのハッシュが変わり、後続のすべてのイベントが無効化されます。

### Merkleツリー検証

ハッシュチェーンと並行してMerkleツリーが維持されます。これによりO(log n)のメンバーシップ証明が可能になり、特定のイベントが台帳に存在し改ざんされていないことを、他のすべてのイベントをチェックすることなく検証できます。

### 因果DAG再構築

意思決定再構築器は台帳イベントを分析し、3種類の因果エッジを推論します：

1. **時間的** — イベントの順序関係
2. **データフロー** — あるイベントの入力が別のイベントの出力を参照する場合
3. **ツール呼び出し** — セッション内の関数からツールへの呼び出し

これにより、後方に遡って根本原因を見つけたり、前方に追跡して反事実的影響分析を行ったりできるDAGが生成されます。

## 要件

- Python 3.11+
- 依存関係: `pydantic>=2.0`, `rich>=13.0`, `typer>=0.9`, `httpx>=0.25`, `pyyaml>=6.0`

## ライセンス

BSL-1.1 (Business Source License 1.1)
