# Author: @b1bek
from dataclasses import dataclass
from pathlib import Path

DEFAULT_PLUGINS_DIR = Path("plugins")
DEFAULT_MODEL = "claude-opus-4-6"
VERIFY_MODEL = "claude-haiku-4-5-20251001"

MODEL_PRICING: dict[str, tuple[float, float]] = {
    "claude-opus-4-6": (5.0, 25.0),
    "claude-opus-4-5": (5.0, 25.0),
    "claude-opus-4-1": (15.0, 75.0),
    "claude-opus-4": (15.0, 75.0),
    "claude-sonnet-4-6": (3.0, 15.0),
    "claude-sonnet-4-5": (3.0, 15.0),
    "claude-sonnet-4": (3.0, 15.0),
    "claude-haiku-4-5-20251001": (1.0, 5.0),
    "claude-haiku-4-5": (1.0, 5.0),
}


@dataclass
class TokenUsage:
    input_tokens: int = 0
    output_tokens: int = 0
    cache_creation_input_tokens: int = 0
    cache_read_input_tokens: int = 0
    model: str = ""

    def cost_usd(self) -> float:
        price_in, price_out = MODEL_PRICING.get(self.model, (0.0, 0.0))
        # Cache writes cost 1.25x, cache reads cost 0.1x, regular input costs 1x
        return (
            self.input_tokens * price_in
            + self.output_tokens * price_out
            + self.cache_creation_input_tokens * price_in * 1.25
            + self.cache_read_input_tokens * price_in * 0.10
        ) / 1_000_000

    def __iadd__(self, other: "TokenUsage") -> "TokenUsage":
        self.input_tokens += other.input_tokens
        self.output_tokens += other.output_tokens
        self.cache_creation_input_tokens += other.cache_creation_input_tokens
        self.cache_read_input_tokens += other.cache_read_input_tokens
        return self

    def __bool__(self) -> bool:
        return self.input_tokens > 0 or self.output_tokens > 0
