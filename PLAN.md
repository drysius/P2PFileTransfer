# Plano de Projeto — `xfer`

Transferência P2P de arquivos e pastas, escrita do zero em Rust.
Documento de referência para o novo repositório. Autossuficiente — pode ser movido para a raiz do repo novo sem edição.

**Status:** plano aprovado, implementação não iniciada.
**Data:** 2026-08-13

---

## 0. Sumário das decisões

| Eixo | Decisão | Alternativas descartadas |
|---|---|---|
| Transporte | **QUIC** via `quinn`, 1 conexão + N streams | TCP com framing próprio; TCP+TLS multi-conexão |
| Unidade de transferência | **1 stream por arquivo**, corpo em bytes crus | chunking na aplicação com ACK/janela deslizante |
| Resume | **offset de byte** por arquivo | bitmap de chunks |
| Hash | **BLAKE3** | SHA-256 |
| Modelo de sync | **push tipo rsync** (remetente manda o delta) | push+pull bidirecional; sync contínuo com watch |
| Segurança | cifra sempre (TLS 1.3 do QUIC); autenticação por pareamento, com `--insecure` para LAN | texto claro; sem escape para LAN |
| Interface | **só CLI** (lib `xfer-core` + binário `xfer`) | CLI+GUI simultâneos; daemon |
| Estado | **ator único** dono do estado, persistência append-only | arquivo JSON compartilhado entre tasks |

### Nota sobre `--insecure`

QUIC exige TLS 1.3 pela especificação — não existe QUIC em texto claro. Portanto `--insecure` significa **sem autenticação de peer** (aceita certificado self-signed, sem código de pareamento), **não** "sem criptografia".

Isso é aceitável: AES-NI e ChaCha20 entregam 2–6 GB/s por core. Em rede de 1–10 Gbps o gargalo é o disco, não a cifra. Consequência prática: não existe caminho de código duplo "cifrado/não cifrado" — só um caminho, com política de verificação de certificado variável.

---

## 1. Contexto: o que estamos corrigindo

Este plano nasce da análise de um projeto anterior (`P2PFileTransfer`, ~11.6k linhas). Os problemas encontrados lá definem as restrições de desenho aqui. Referência rápida:

| Problema no projeto anterior | Como o novo desenho impede |
|---|---|
| Chunk duplicado escrito e hasheado duas vezes → SHA divergente | Sem chunks na aplicação; stream QUIC é ordenado e sem duplicata |
| Chunk estourando `max_retries` sumia em silêncio → loop infinito | Retransmissão é do QUIC; falha de stream é erro tipado que sobe |
| Resume parcial nunca ativado (função nunca chamada, código morto) | Resume por offset é o único caminho; sem ele não há retomada |
| Race no arquivo de estado com N conexões paralelas | Estado tem dono único (ator); ninguém mais toca |
| SHA-256 calculado na ordem de chegada, não na ordem do arquivo | Stream ordenado ⇒ ordem de chegada **é** a ordem do arquivo |
| `output_dir.join(string_do_peer)` → path traversal | `SafeRelPath`: só construível via validação |
| `vec![0u8; len]` com `len` do peer (até 128 MB) antes de autenticar | `max_frame_length` pequeno no codec; buffers de pool |
| Crate de GUI fora do CI apodreceu até não compilar | Regra: nada fora de `--all-features` no CI |
| Rehash de toda a pasta a cada envio | Cache de hash por `(path, size, mtime)` |
| `send_file` e `send_file_windowed` ~90% duplicados | Um único caminho de envio |

### O que vale a pena preservar do projeto anterior

- Fila de trabalho com work-stealing por lotes (arquivos maior-primeiro) — a distribuição funcionava bem.
- Decisão de compressão por extensão (lista de formatos já comprimidos) + amostragem adaptativa.
- Escrita em `.part` seguida de rename atômico.
- Bits de capacidade negociados no handshake.
- Separação de crates com o core sem dependências de UI.

---

## 2. Estrutura do workspace

```
xfer/
├── Cargo.toml                  # workspace
├── PLAN.md                     # este documento
├── xfer-core/                  # biblioteca pura — sem clap, sem indicatif, sem anyhow
│   └── src/
│       ├── lib.rs
│       ├── error.rs            # thiserror, erros tipados
│       ├── proto/              # tipos de wire, codec, versionamento
│       │   ├── mod.rs
│       │   ├── messages.rs     # enum Control, headers de stream de dados
│       │   ├── codec.rs        # LengthDelimitedCodec + postcard
│       │   └── version.rs      # negociação de versão e features
│       ├── transport/          # quinn
│       │   ├── mod.rs
│       │   ├── endpoint.rs     # bind, connect, config de TLS
│       │   ├── tls.rs          # rcgen, verificador custom, pareamento
│       │   └── session.rs      # conexão + stream de controle + abertura de streams
│       ├── safety/
│       │   ├── mod.rs
│       │   ├── path.rs         # SafeRelPath
│       │   └── limits.rs       # todos os limites em um lugar
│       ├── scan/
│       │   ├── mod.rs
│       │   ├── walk.rs         # jwalk paralelo
│       │   ├── hash_cache.rs   # cache (path, size, mtime) → hash
│       │   └── manifest.rs     # construção e lotes
│       ├── pipeline/
│       │   ├── mod.rs
│       │   ├── send.rs
│       │   ├── recv.rs
│       │   ├── budget.rs       # semáforos, orçamento de memória
│       │   └── bufpool.rs
│       ├── state/
│       │   ├── mod.rs          # ator
│       │   ├── journal.rs      # append-only + snapshot
│       │   └── model.rs
│       ├── compress.rs
│       └── metrics.rs          # ator de métricas/progresso
├── xfer-cli/                   # clap + indicatif; fino, zero lógica de protocolo
│   └── src/
│       ├── main.rs
│       ├── args.rs
│       ├── send.rs
│       ├── recv.rs
│       └── ui.rs               # barras, formatação
├── xfer-fuzz/                  # cargo-fuzz
│   └── fuzz_targets/
│       ├── decode_control.rs
│       └── safe_path.rs
├── xtask/                      # cargo xtask ci — roda o pipeline local
└── tests/                      # integração + injeção de falha
    ├── common/
    │   ├── harness.rs          # par sender/receiver em loopback
    │   └── faults.rs           # corte de conexão, corrupção, lentidão
    ├── roundtrip.rs
    ├── resume.rs
    ├── sync_skip.rs
    └── path_safety.rs
```

**Regra de dependência (verificada no CI):** `xfer-core` não pode depender de `clap`, `indicatif`, `anyhow` nem de nada de UI. Erros no core são `thiserror` tipados; `anyhow` existe só no `xfer-cli`.

---

## 3. Modelo de threading

Três pools, com papéis que não se misturam:

```
┌─ Tokio (multi_thread, worker_threads = n_cores) ──────────┐
│  tasks de rede: 1 por stream ativo, + controle + atores   │  nunca bloqueia
└───────────────────────────────────────────────────────────┘
┌─ Rayon ───────────────────────────────────────────────────┐
│  CPU: BLAKE3, zstd encode/decode                           │  nunca faz I/O
└───────────────────────────────────────────────────────────┘
┌─ spawn_blocking (pool dedicado) ──────────────────────────┐
│  disco: read, write, fsync, rename                         │  nunca faz CPU pesado
└───────────────────────────────────────────────────────────┘
```

### Pipeline por arquivo

```
ENVIO
  disco.read ──buf──▶ [zstd (rayon)] ──buf──▶ quinn.write
       └───────────────────────────▶ blake3 incremental (rayon)

RECEPÇÃO
  quinn.read ──buf──▶ [zstd (rayon)] ──buf──▶ disco.write
                              └──────────────▶ blake3 incremental (rayon)
```

Etapas ligadas por `tokio::sync::mpsc` com **capacidade limitada** (2–4 buffers). Backpressure é consequência: canal cheio ⇒ o leitor de disco para ⇒ a memória não cresce.

### Orçamento de memória

`--mem-budget` (default ~256 MB) é a entrada; a concorrência é derivada dela, nunca o contrário:

```
streams_simultaneos = clamp(mem_budget / (buf_size * profundidade_pipeline), 1, limite_quic)
```

### Semáforos (independentes, configuráveis)

| Semáforo | Default | Motivo de ser separado |
|---|---|---|
| `disk_read` | 4 | HDD degrada com concorrência alta; NVMe se beneficia |
| `disk_write` | 4 | escrita é mais cara que leitura |
| `cpu` | n_cores | limita a fila entregue ao rayon |
| `net_streams` | 16 | QUIC negocia limite de streams concorrentes |

Expostos como `--disk-read-jobs`, `--disk-write-jobs`, `--streams`. Sem autodetecção mágica de HDD vs SSD — flag explícita, default conservador.

### Pool de buffers

Buffers reaproveitados (`bytes::BytesMut` com pool próprio ou slab). Zero alocação por bloco no caminho quente. O dado nasce em um buffer, é processado nele e volta ao pool.

### Fila de trabalho

Arquivos ordenados maior-primeiro em fila compartilhada; workers puxam lotes (limite por bytes **e** por contagem de arquivos, para que ninguém monopolize milhares de arquivos pequenos). Cada worker roda o pipeline acima em seu próprio stream.

---

## 4. Protocolo

### Stream de controle

Bidirecional, aberto logo após o handshake, vive a sessão inteira.

```rust
enum Control {
    Hello       { version: u16, features: u64, device: [u8; 32] },
    HelloAck    { version: u16, features: u64, device: [u8; 32] },

    Manifest    { batch_seq: u32, last: bool, entries: Vec<Entry> },
    SyncReply   { batch_seq: u32, decisions: Vec<Decision> },

    FileDone    { file_id: u64, hash: [u8; 32] },   // remetente: terminei, este é o hash
    FileVerdict { file_id: u64, ok: bool },         // receptor: confere / não confere

    Done        { files: u64, bytes: u64 },
    Error       { code: ErrorCode, msg: String },
}

struct Entry {
    file_id: u64,
    path: Vec<String>,      // componentes, NÃO string com separador
    size: u64,
    mtime: u64,
    mode: u32,              // bits relevantes por plataforma
    hash: Option<[u8; 32]>, // ausente para arquivos grandes / sem cache
}

enum Decision {
    Skip,
    Need { file_id: u64, from_offset: u64 },
}
```

### Streams de dados

Unidirecionais, um por arquivo. Header curto, corpo cru, fim do stream = fim do arquivo.

```rust
struct DataHeader {
    file_id: u64,
    offset: u64,        // de onde este stream começa (resume)
    compressed: bool,
}
```

Sem framing por bloco. Sem CRC por bloco — a AEAD do QUIC já garante integridade no transporte; o BLAKE3 por arquivo cobre erro de disco e bug de aplicação, que é onde ele agrega.

### Regras de codec

- Serialização: `postcard` (compacto, rápido, estável) sobre `serde`.
- Framing do controle: `tokio_util::codec::LengthDelimitedCodec` com `max_frame_length` pequeno (4 MB). Nunca alocar com tamanho vindo do peer sem teto.
- Envelope com `version: u16` + `features: u64` explícitos. Campo novo entra como feature bit; peer antigo ignora com segurança.
- Manifesto **sempre** em lotes (ex.: 2000 entradas por mensagem), independente do tamanho da pasta.
- `file_id` recebido em stream de dados precisa existir no manifesto negociado e estar marcado como `Need`. Caso contrário: erro, não warning.

---

## 5. Segurança

### Path — o tipo carrega a garantia

```rust
pub struct SafeRelPath(PathBuf);   // construtor privado

impl SafeRelPath {
    pub fn from_components(parts: &[String]) -> Result<Self, PathError>;
    pub fn resolve_under(&self, root: &Path) -> Result<PathBuf, PathError>;
}
```

O construtor rejeita:

- componente vazio, `.` ou `..`
- separador (`/` ou `\`) dentro de um componente
- prefixo absoluto, prefixo de drive (`C:`), UNC (`\\server\share`), `\\?\`
- nomes reservados do Windows: `CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9` (com ou sem extensão)
- ponto ou espaço final em qualquer componente (Windows os remove silenciosamente)
- caracteres de controle (`\0`–`\x1F`) e, em Windows, `<>:"|?*`
- profundidade acima do limite; comprimento total acima do limite

`resolve_under` canonicaliza o diretório pai e afirma `starts_with(root)` antes de devolver. Coberto por proptest e por alvo de fuzz.

### Symlinks

Padrão: ignorados no scan. `--follow-links` para seguir na leitura. **Nunca** criar symlink a partir do manifesto sem `--links` explícito — senão é escrita fora da raiz por outra porta.

### Autenticação

- **Padrão:** receptor exibe um código curto de pareamento; remetente digita. O código deriva a chave da sessão (PAKE, ou PSK simples na v1 com upgrade planejado). Sem código correto, sem sessão.
- **`--insecure`:** aceita certificado self-signed sem pareamento. Imprime aviso visível. Nunca é o comportamento silencioso.
- **TOFU opcional (fase posterior):** keypair persistente por peer, confirmação de fingerprint na primeira conexão, reconexão automática depois.

### Limites (todos em `safety/limits.rs`, todos configuráveis)

`max_frame_length` · `max_manifest_entries` · `max_path_depth` · `max_path_len` · `max_concurrent_streams` · `handshake_timeout` · `idle_timeout` · `max_file_size`

---

## 6. Estado e resume

### Ator de estado

Uma task é dona do estado. Ninguém mais abre o arquivo. Comunicação por canal:

```rust
enum StateMsg {
    Recorded { file_id: u64, path: SafeRelPath, size: u64, mtime: u64, hash: [u8; 32] },
    Progress { file_id: u64, bytes_on_disk: u64 },
    Query    { path: SafeRelPath, reply: oneshot::Sender<Option<Record>> },
    Flush    { reply: oneshot::Sender<()> },
}
```

Isso torna a race do projeto anterior impossível por construção, não por disciplina.

### Persistência

Journal append-only (`.xfer/journal`) + snapshot periódico gravado em arquivo temporário e movido com rename atômico. Sem dependência C, sem lock de arquivo, sem escrita concorrente. Na abertura: carrega snapshot, reaplica o journal, compacta.

### Resume por offset

1. Receptor tem `bytes_on_disk` do `.part` (confirmado por `metadata().len()`, não só pelo journal).
2. Ao responder o manifesto, devolve `Need { from_offset }`.
3. Remetente faz `seek(offset)` e abre o stream com esse offset no header.
4. Ambos os lados alimentam o BLAKE3 na ordem do arquivo — o receptor rehasheia o prefixo já em disco antes de continuar (ou, melhor, guarda o estado do hasher no journal quando disponível).

Como o stream é ordenado, o que está em disco é sempre um prefixo válido. Não existe bitmap, não existe buraco no meio, não existe ordem de chegada divergente.

---

## 7. Scan, manifesto e diff

- Walk paralelo com `jwalk` (usa rayon internamente).
- **Cache de hash local** em `.xfer/hashcache`, chaveado por `(path, size, mtime)` — e `inode`/`file_index` onde disponível. Evita rehash da pasta inteira a cada envio, que era o maior custo do projeto anterior.
- Arquivos acima de um limite (ex.: 1 GB) entram no manifesto sem hash (`hash: None`); o receptor decide por `size + mtime`. Com `--checksum`, hasheia tudo.
- Decisão do receptor, por entrada:
  - `size` diferente → `Need { from_offset: bytes_on_disk }`
  - `size` igual e hash presente nos dois lados → compara hash → `Skip` ou `Need`
  - `size` igual, sem hash → compara `mtime` → `Skip` ou `Need`
  - arquivo em disco mas fora do journal, com hash do remetente → hasheia local e compara (recupera de journal apagado)
- `--dry-run` executa exatamente esse diálogo e imprime o resultado sem abrir nenhum stream de dados.

---

## 8. Compressão

- zstd **streaming por arquivo** (`zstd::stream::Encoder` sobre o pipeline), não por bloco.
- Decisão feita uma vez por arquivo, antes de abrir o stream:
  1. extensão em lista de formatos já comprimidos (`zip`, `mp4`, `jpg`, `7z`, `pdf`, `docx`, …) → não comprime;
  2. senão, amostra os primeiros ~256 KB; se a razão ficar abaixo de ~1.05, não comprime.
- A decisão vai no `DataHeader.compressed` — o receptor obedece o flag, nunca a configuração global. (Bug clássico: receptor decidindo por config enquanto o remetente decide por arquivo.)
- Compressão e descompressão rodam no pool de CPU, nunca na task de rede.

---

## 9. Observabilidade

- `tracing` em todo o core; `tracing-subscriber` no CLI, com `--log-format=text|json`.
- Ator de métricas agrega contadores atômicos; a UI lê snapshots. Nada de barra de progresso passeando por dentro da lógica de transferência (o projeto anterior enfiava `&mut ProgressState` em seis assinaturas).
- Por padrão: uma barra global. `--verbose`: uma barra por stream.
- `--stats` no fim: arquivos, bytes lidos/enviados, razão de compressão, throughput de rede vs de disco, tempo por fase (scan, hash, transferência), streams e retries.

---

## 10. Fases

Cada fase termina com CI verde e binário utilizável. Nada de "termino na próxima fase".

### F0 — Esqueleto
Workspace, tipos de erro, `tracing`, `xtask ci`.
CI completo **desde o primeiro commit**: `fmt --check`, `clippy --all-targets --all-features -D warnings`, `test --all-features`, `cargo-deny`, matriz Linux/Windows/macOS.
**Pronto quando:** `cargo xtask ci` reproduz o pipeline localmente e o CI está verde.

### F1 — Transporte
`quinn` + `rustls` + `rcgen`. Endpoint cliente/servidor, handshake `Hello`/`HelloAck`, codec do stream de controle, negociação de versão e features.
**Pronto quando:** teste de integração conecta em loopback, negocia e troca mensagens de controle; versão incompatível é rejeitada com erro tipado.

### F2 — Um arquivo
Envio e recepção de arquivo único. Sem compressão, sem paralelismo. `.part` → BLAKE3 → verificação ponta a ponta → rename atômico.
**Pronto quando:** arquivo de 1 GB atravessa com hash conferindo; byte corrompido injetado é detectado e reportado.

### F3 — Manifesto e diff
Walk paralelo, cache de hash, manifesto em lotes, `Skip`/`Need`, `--dry-run`.
**Pronto quando:** segunda execução sobre pasta idêntica transfere 0 bytes; alterar um arquivo transfere apenas ele; `--dry-run` bate com o que a execução real faz.

### F4 — Paralelismo
Fila de trabalho, N streams, os quatro semáforos, canais limitados, pool de buffers.
**Pronto quando:** benchmark mostra escala com `--streams`; o pico de RSS respeita `--mem-budget` sob carga; sem `unwrap` no caminho quente.

### F5 — Resume
Ator de estado, journal + snapshot, retomada por offset, reconexão com backoff.
**Pronto quando:** o harness de falha mata a conexão em 100 pontos aleatórios e a árvore final é byte-idêntica nas 100 vezes.

### F6 — Compressão
zstd streaming, decisão por extensão + amostra, flag no header.
**Pronto quando:** pasta de texto comprime; pasta de mp4/zip passa direto sem custo de CPU mensurável; receptor respeita o flag por arquivo.

### F7 — Segurança
Pareamento, `--insecure` com aviso, todos os limites aplicados, fuzz do decoder e do `SafeRelPath`, suíte de path traversal (incluindo os casos de Windows).
**Pronto quando:** fuzz roda 1 h sem crash; todos os vetores de traversal são rejeitados; peer sem pareamento não escreve nada em disco.

### F8 — Acabamento
Barras de progresso, `--stats`, limite de banda (token bucket), descoberta na LAN (opcional), mensagens de erro legíveis, `--help` completo.

### F9 — Endurecimento
Property tests, benchmarks com `criterion`, teste de interop entre versões (arquivos golden do wire format), documentação do protocolo, notas de release.

---

## 11. Estratégia de teste

Ponto fraco do projeto anterior; aqui é requisito de fase.

- **Unitário:** sanitizador de path, codec/framing, diff do manifesto, aritmética de offset de resume, decisão de compressão.
- **Property (`proptest`):** para qualquer conjunto de arquivos e qualquer ponto de interrupção, o resume produz árvore byte-idêntica. Para qualquer entrada, `SafeRelPath` ou rejeita ou resolve dentro da raiz.
- **Integração:** par sender/receiver em processo, QUIC em loopback, com camada de injeção de falha: cortar conexão após N bytes, corromper payload, atrasar, encher o disco, negar permissão.
- **Fuzz (`cargo-fuzz`):** decoder de controle e `SafeRelPath`.
- **Interop:** arquivos golden do wire format versionados no repo, para que uma mudança acidental de protocolo quebre o teste.
- **Bench (`criterion`):** throughput por número de streams, custo do hash, custo da compressão, tempo de scan com cache quente e frio.

---

## 12. Dependências

`quinn` · `rustls` · `rcgen` · `tokio` · `tokio-util` · `bytes` · `serde` · `postcard` · `blake3` · `zstd` · `jwalk` · `rayon` · `tracing` · `tracing-subscriber` · `thiserror` · `clap` · `indicatif` · `proptest` · `criterion` · `cargo-deny` · `cargo-fuzz`

`anyhow` apenas em `xfer-cli`.

---

## 13. Regras do projeto

1. **Nada fora do CI.** Todo crate entra em `cargo check --all-features`. Se não compila no CI, não existe.
2. **Sem código morto.** `dead_code` é warning tratado como erro. Função sem chamador é deletada, não comentada.
3. **Segurança é tipo, não convenção.** Se a garantia depende de alguém lembrar de chamar uma função, o desenho está errado.
4. **Estado mutável tem dono único.** Precisar de `Mutex` no caminho quente é sinal de desenho errado.
5. **Cada fase entrega binário funcionando.**
6. **Teste de falha antes de otimização.** Interrupção, corrupção, disco cheio, peer lento, peer malicioso.
7. **Sem `unwrap`/`expect` no core** fora de invariantes provadas, comentadas na hora.
8. **Uma forma de fazer cada coisa.** Se aparecer um segundo caminho de envio, um deles some.

---

## 14. Fora de escopo (v1)

Anotado para não virar escopo por acidente:

- GUI
- Sync contínuo com watch de diretório
- Sync bidirecional com resolução de conflito
- Delta intra-arquivo estilo rsync (rolling hash) — v1 retoma por offset, não por bloco
- Travessia de NAT / relay / hole punching
- Múltiplos peers simultâneos numa mesma sessão
- Preservação de ACL e metadados estendidos além de `mode` e `mtime`
