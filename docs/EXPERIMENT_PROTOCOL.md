# Experiment protocol

1. Freeze source revision, rights decision, raw checksum and transformation version.
2. Freeze source scenario/document families and benchmark reference material.
3. Review privacy quarantines and answers. Preserve weak/synthetic labels.
4. Inspect the exact installed Qwen3 MoE config and chat tokenizer, without inferring
   architecture from the model name. Record their hashes in the build manifest.
5. Use a production configuration with local tokenizer, whole-record length
   rejection and seed 42. Inspect both sample and token category distributions.
6. Audit split reports and compare near-duplicate threshold sensitivity. Freeze
   assignments rather than rebuilding splits after arbitrary source additions.
7. Check the installed MLX-FUN tokenization function, then run real tokenizer
   round trips for tool `content` exports, including special-token handling.
8. In a separately authorized later phase, calibrate routing using calibration
   only; train recovery/adapters using train and validation; score evaluation only.

The initial 512 targets are hypotheses. Shortfalls must be resolved through
legitimate reviewed data, not duplication or synthetic filler. Evaluation prompts
and answers are independent artifacts; official benchmark scoring remains required.
Track manifests, source rights, tokenizer hashes, seed, sequence limits and tool
schemas with each experiment. Compare unpruned baseline against later pruned and
recovered variants under identical held-out conditions.

Selectively training experts requires empirical routing observations, parameter
selection checks and regression evaluation. Domain labels alone are insufficient.
No pruning percentage, expert count, LoRA rank or routing strategy is assumed here.
