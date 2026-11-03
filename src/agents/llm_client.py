"""
llm_client.py
Lớp bọc DUY NHẤT để gọi LLM. Reviewer/Fixer chỉ gọi qua đây, không gọi
Ollama trực tiếp, nên đổi model hay provider chỉ phải sửa file này.
"""

import os
import time
from typing import Optional

import requests
from pydantic import BaseModel


class LLMError(Exception):
    """Lỗi kỹ thuật khi gọi LLM: mạng, timeout, HTTP lỗi, phản hồi hỏng."""


class LLMResponse(BaseModel):
    content: str
    model: str
    latency_sec: float
    prompt_tokens: Optional[int] = None
    completion_tokens: Optional[int] = None
    done_reason: Optional[str] = None


class OllamaClient:
    def __init__(
        self,
        model: str = "qwen2.5-coder:3b",
        base_url: Optional[str] = None,
        timeout_sec: float = 120.0,
        temperature: float = 0.0,
        seed: int = 42,
        num_ctx: int = 8192,
        keep_alive: str = "10m",
        num_predict: int = 500,
        repeat_penalty: Optional[float] = None,
        repeat_last_n: Optional[int] = None,
    ):
        self.model = model
        self.base_url = (base_url or os.environ.get("OLLAMA_BASE_URL")
                         or "http://localhost:11434").rstrip("/")
        self.timeout_sec = timeout_sec
        self.temperature = temperature
        self.seed = seed
        self.num_ctx = num_ctx
        self.keep_alive = keep_alive
        self.num_predict = num_predict
        self.repeat_penalty = repeat_penalty
        self.repeat_last_n = repeat_last_n

    def list_models(self) -> list[str]:
        try:
            r = requests.get(f"{self.base_url}/api/tags", timeout=5)
            r.raise_for_status()
            return [m["name"] for m in r.json().get("models", [])]
        except requests.RequestException as e:
            raise LLMError(f"Không kết nối được Ollama tại {self.base_url}: {e}") from e

    def is_available(self) -> bool:
        try:
            return self.model in self.list_models()
        except LLMError:
            return False

    def chat(self, system: str, user: str,
             json_schema: Optional[dict] = None) -> LLMResponse:
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": False,
            "keep_alive": self.keep_alive,
            "options": {
                "temperature": self.temperature,
                "seed": self.seed,
                "num_ctx": self.num_ctx,
                "num_predict": self.num_predict,
            },
        }
        if json_schema is not None:
            payload["format"] = json_schema   # structured output
        if self.repeat_penalty is not None:
            payload["options"]["repeat_penalty"] = self.repeat_penalty
        if self.repeat_last_n is not None:
            payload["options"]["repeat_last_n"] = self.repeat_last_n

        start = time.perf_counter()
        try:
            r = requests.post(f"{self.base_url}/api/chat", json=payload,
                              timeout=self.timeout_sec)
        except requests.Timeout as e:
            raise LLMError(f"Timeout sau {self.timeout_sec}s") from e
        except requests.RequestException as e:
            raise LLMError(f"Lỗi kết nối: {e}") from e
        latency = time.perf_counter() - start

        if r.status_code != 200:
            raise LLMError(f"HTTP {r.status_code}: {r.text[:300]}")

        try:
            data = r.json()
            content = data["message"]["content"]
        except (ValueError, KeyError) as e:
            raise LLMError(f"Phản hồi không đúng định dạng: {r.text[:300]}") from e

        return LLMResponse(
            content=content,
            model=self.model,
            latency_sec=round(latency, 2),
            prompt_tokens=data.get("prompt_eval_count"),
            completion_tokens=data.get("eval_count"),
            done_reason=data.get("done_reason"),
        )