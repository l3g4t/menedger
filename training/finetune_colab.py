"""
training/finetune_colab.py — LoRA-дообучение Qwen2.5-0.5B-Instruct в Google Colab
и экспорт в .gguf (CLAUDE.md, раздел 9.4). DEV-ONLY, в приложение не входит.

НЕ ПРОВЕРЕНО: скрипт написан по документации `unsloth`/`trl`, но не запускался
(в среде разработки нет GPU и нет доступа к Hugging Face). Сигнатуры в этих
библиотеках меняются между версиями — если Colab выдаст ошибку в
`SFTConfig`/`save_pretrained_gguf`, сверьтесь с актуальным ноутбуком unsloth
для Qwen2.5 (раздел «Conversational»).

Как запускать (Colab, среда выполнения «T4 GPU»):
  1. Загрузите `training/data/dataset.jsonl` в файлы Colab.
  2. В первой ячейке:  !pip install unsloth
  3. Вставьте этот файл целиком во вторую ячейку и запустите.
  4. Скачайте получившийся `.gguf` (папка `assistant_model_gguf/`), переименуйте
     в `assistant_model.gguf` и положите рядом с приложением (README).
"""

from datasets import load_dataset
from trl import SFTConfig, SFTTrainer
from unsloth import FastLanguageModel

BASE_MODEL = "unsloth/Qwen2.5-0.5B-Instruct"
MAX_SEQ_LENGTH = 2048

model, tokenizer = FastLanguageModel.from_pretrained(
    model_name=BASE_MODEL,
    max_seq_length=MAX_SEQ_LENGTH,
    load_in_4bit=False,  # модель крошечная — квантование при обучении не нужно
)

# LoRA: замороженная база + маленькая обучаемая «надстройка» (раздел 9.2).
model = FastLanguageModel.get_peft_model(
    model,
    r=16,
    lora_alpha=16,
    lora_dropout=0,
    target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
    use_gradient_checkpointing="unsloth",
    random_state=3407,
)

dataset = load_dataset("json", data_files="dataset.jsonl", split="train")


def to_text(batch):
    # Шаблон чата Qwen: тот же, по которому llama.cpp будет формировать
    # запрос в приложении (`create_chat_completion` берёт шаблон из .gguf).
    return {
        "text": [
            tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=False)
            for messages in batch["messages"]
        ]
    }


dataset = dataset.map(to_text, batched=True)

trainer = SFTTrainer(
    model=model,
    tokenizer=tokenizer,
    train_dataset=dataset,
    args=SFTConfig(
        dataset_text_field="text",
        max_seq_length=MAX_SEQ_LENGTH,
        per_device_train_batch_size=4,
        gradient_accumulation_steps=2,
        num_train_epochs=3,
        learning_rate=2e-4,
        warmup_steps=5,
        logging_steps=5,
        optim="adamw_8bit",
        seed=3407,
        output_dir="outputs",
        report_to="none",
    ),
)
trainer.train()

# unsloth сам сливает LoRA с базовой моделью и конвертирует в GGUF (Q4_K_M ≈ 0,4 ГБ).
model.save_pretrained_gguf("assistant_model_gguf", tokenizer, quantization_method="q4_k_m")
