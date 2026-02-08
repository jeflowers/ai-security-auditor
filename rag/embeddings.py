"""
Embedding Service for RAG Pipeline

Abstracts embedding generation to support multiple providers:
- OpenAI (text-embedding-3-small, text-embedding-3-large)
- Local models (sentence-transformers)
- Future: NVIDIA NIM embeddings

Includes caching to reduce API costs and improve latency.
"""

import hashlib
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
import asyncio


@dataclass
class EmbeddingResult:
    """Result from embedding generation."""
    text: str
    embedding: list[float]
    model: str
    dimensions: int
    cached: bool = False


class EmbeddingService(ABC):
    """Abstract base class for embedding services."""
    
    @property
    @abstractmethod
    def model_name(self) -> str:
        """Name of the embedding model."""
        pass
    
    @property
    @abstractmethod
    def dimensions(self) -> int:
        """Dimensionality of embeddings."""
        pass
    
    @abstractmethod
    async def embed_text(self, text: str) -> list[float]:
        """Generate embedding for a single text."""
        pass
    
    @abstractmethod
    async def embed_batch(self, texts: list[str]) -> list[list[float]]:
        """Generate embeddings for multiple texts."""
        pass


class EmbeddingCache:
    """
    Disk-based cache for embeddings.
    
    Reduces API costs by caching embeddings keyed by content hash.
    """
    
    def __init__(self, cache_dir: Path):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.index_path = self.cache_dir / "index.json"
        self.index = self._load_index()
    
    def _load_index(self) -> dict:
        """Load cache index from disk."""
        if self.index_path.exists():
            with open(self.index_path, 'r') as f:
                return json.load(f)
        return {}
    
    def _save_index(self):
        """Save cache index to disk."""
        with open(self.index_path, 'w') as f:
            json.dump(self.index, f)
    
    def _hash_text(self, text: str, model: str) -> str:
        """Generate cache key from text and model."""
        content = f"{model}:{text}"
        return hashlib.sha256(content.encode()).hexdigest()
    
    def get(self, text: str, model: str) -> Optional[list[float]]:
        """Get cached embedding if available."""
        cache_key = self._hash_text(text, model)
        if cache_key in self.index:
            embedding_path = self.cache_dir / f"{cache_key}.json"
            if embedding_path.exists():
                with open(embedding_path, 'r') as f:
                    data = json.load(f)
                return data["embedding"]
        return None
    
    def set(self, text: str, model: str, embedding: list[float]):
        """Cache an embedding."""
        cache_key = self._hash_text(text, model)
        embedding_path = self.cache_dir / f"{cache_key}.json"
        
        with open(embedding_path, 'w') as f:
            json.dump({
                "text_preview": text[:100],
                "model": model,
                "embedding": embedding
            }, f)
        
        self.index[cache_key] = {
            "model": model,
            "text_length": len(text)
        }
        self._save_index()


class OpenAIEmbeddingService(EmbeddingService):
    """
    OpenAI embedding service.
    
    Supports:
    - text-embedding-3-small (1536 dims, cheaper)
    - text-embedding-3-large (3072 dims, better quality)
    - text-embedding-ada-002 (1536 dims, legacy)
    """
    
    MODEL_DIMENSIONS = {
        "text-embedding-3-small": 1536,
        "text-embedding-3-large": 3072,
        "text-embedding-ada-002": 1536,
    }
    
    def __init__(
        self,
        api_key: str = None,
        model: str = "text-embedding-3-small",
        cache_dir: Path = None
    ):
        self._model = model
        self._dimensions = self.MODEL_DIMENSIONS.get(model, 1536)
        self.cache = EmbeddingCache(cache_dir) if cache_dir else None
        
        # Import here to avoid dependency issues
        from openai import AsyncOpenAI
        self.client = AsyncOpenAI(api_key=api_key)
    
    @property
    def model_name(self) -> str:
        return self._model
    
    @property
    def dimensions(self) -> int:
        return self._dimensions
    
    async def embed_text(self, text: str) -> list[float]:
        """Generate embedding for a single text."""
        # Check cache first
        if self.cache:
            cached = self.cache.get(text, self._model)
            if cached:
                return cached
        
        response = await self.client.embeddings.create(
            input=text,
            model=self._model
        )
        embedding = response.data[0].embedding
        
        # Cache the result
        if self.cache:
            self.cache.set(text, self._model, embedding)
        
        return embedding
    
    async def embed_batch(self, texts: list[str]) -> list[list[float]]:
        """Generate embeddings for multiple texts."""
        # Check cache for each text
        results = [None] * len(texts)
        uncached_indices = []
        uncached_texts = []
        
        if self.cache:
            for i, text in enumerate(texts):
                cached = self.cache.get(text, self._model)
                if cached:
                    results[i] = cached
                else:
                    uncached_indices.append(i)
                    uncached_texts.append(text)
        else:
            uncached_indices = list(range(len(texts)))
            uncached_texts = texts
        
        # Fetch uncached embeddings
        if uncached_texts:
            # OpenAI supports batching up to ~8000 tokens per request
            # We'll batch in groups of 100 texts
            batch_size = 100
            for batch_start in range(0, len(uncached_texts), batch_size):
                batch_end = min(batch_start + batch_size, len(uncached_texts))
                batch = uncached_texts[batch_start:batch_end]
                
                response = await self.client.embeddings.create(
                    input=batch,
                    model=self._model
                )
                
                for j, embedding_data in enumerate(response.data):
                    idx = uncached_indices[batch_start + j]
                    embedding = embedding_data.embedding
                    results[idx] = embedding
                    
                    # Cache the result
                    if self.cache:
                        self.cache.set(texts[idx], self._model, embedding)
        
        return results


class LocalEmbeddingService(EmbeddingService):
    """
    Local embedding service using sentence-transformers.
    
    Good for development and when you want to avoid API costs.
    Recommended models:
    - all-MiniLM-L6-v2 (fast, 384 dims)
    - all-mpnet-base-v2 (better quality, 768 dims)
    - BAAI/bge-small-en-v1.5 (good balance, 384 dims)
    """
    
    MODEL_DIMENSIONS = {
        "all-MiniLM-L6-v2": 384,
        "all-mpnet-base-v2": 768,
        "BAAI/bge-small-en-v1.5": 384,
        "BAAI/bge-base-en-v1.5": 768,
    }
    
    def __init__(
        self,
        model: str = "all-MiniLM-L6-v2",
        device: str = "cpu"
    ):
        self._model_name = model
        self._dimensions = self.MODEL_DIMENSIONS.get(model, 384)
        self.device = device
        self._model = None
    
    def _load_model(self):
        """Lazy load the model."""
        if self._model is None:
            from sentence_transformers import SentenceTransformer
            self._model = SentenceTransformer(self._model_name, device=self.device)
    
    @property
    def model_name(self) -> str:
        return self._model_name
    
    @property
    def dimensions(self) -> int:
        return self._dimensions
    
    async def embed_text(self, text: str) -> list[float]:
        """Generate embedding for a single text."""
        self._load_model()
        # Run in thread pool to avoid blocking
        loop = asyncio.get_event_loop()
        embedding = await loop.run_in_executor(
            None,
            lambda: self._model.encode(text, convert_to_numpy=True).tolist()
        )
        return embedding
    
    async def embed_batch(self, texts: list[str]) -> list[list[float]]:
        """Generate embeddings for multiple texts."""
        self._load_model()
        loop = asyncio.get_event_loop()
        embeddings = await loop.run_in_executor(
            None,
            lambda: self._model.encode(texts, convert_to_numpy=True).tolist()
        )
        return embeddings


def create_embedding_service(
    provider: str = "openai",
    model: str = None,
    cache_dir: Path = None,
    **kwargs
) -> EmbeddingService:
    """
    Factory function to create embedding service.
    
    Args:
        provider: "openai" or "local"
        model: Model name (provider-specific)
        cache_dir: Directory for caching embeddings
        **kwargs: Additional provider-specific arguments
    
    Returns:
        Configured EmbeddingService instance
    """
    if provider == "openai":
        model = model or "text-embedding-3-small"
        return OpenAIEmbeddingService(
            model=model,
            cache_dir=cache_dir,
            **kwargs
        )
    elif provider == "local":
        model = model or "all-MiniLM-L6-v2"
        return LocalEmbeddingService(
            model=model,
            **kwargs
        )
    else:
        raise ValueError(f"Unknown embedding provider: {provider}")
