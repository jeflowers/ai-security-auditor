#!/usr/bin/env python3
"""
RAG Pipeline Demo Script

Demonstrates:
1. Indexing SOC 2 control definitions
2. Indexing anti-hallucination scoring rubric
3. Semantic search for controls
4. Building assessment prompts with retrieved context

Usage:
    # Set your OpenAI API key
    export OPENAI_API_KEY=sk-...
    
    # Run the demo
    python -m scripts.rag_demo
    
    # Or use local embeddings (no API key needed)
    python -m scripts.rag_demo --local
"""

import asyncio
import argparse
import os
from pathlib import Path


async def main(use_local: bool = False, verbose: bool = False):
    """Run the RAG pipeline demo."""
    
    # Get project root
    project_root = Path(__file__).parent.parent
    frameworks_dir = project_root / "frameworks"
    evidence_dir = project_root / "evidence"
    rag_data_dir = project_root / "rag_data"
    
    print("=" * 60)
    print("AI-Powered Security Auditor - RAG Pipeline Demo")
    print("=" * 60)
    print()
    
    # Choose embedding provider
    if use_local:
        print("Using LOCAL embeddings (sentence-transformers)")
        print("Model: all-MiniLM-L6-v2 (384 dimensions)")
        embedding_provider = "local"
        embedding_model = "all-MiniLM-L6-v2"
        api_key = None
    else:
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            print("ERROR: OPENAI_API_KEY not set")
            print("Either set the API key or use --local flag")
            return
        print("Using OpenAI embeddings")
        print("Model: text-embedding-3-small (1536 dimensions)")
        embedding_provider = "openai"
        embedding_model = "text-embedding-3-small"
    
    print()
    
    # Import RAG components
    from rag import (
        ComplianceRAGPipeline,
        create_embedding_service,
        DocumentProcessor
    )
    
    # Create embedding service
    print("1. Creating embedding service...")
    if use_local:
        embedding_service = create_embedding_service(
            provider=embedding_provider,
            model=embedding_model
        )
    else:
        embedding_service = create_embedding_service(
            provider=embedding_provider,
            model=embedding_model,
            api_key=api_key,
            cache_dir=rag_data_dir / "embedding_cache"
        )
    print(f"   Model: {embedding_service.model_name}")
    print(f"   Dimensions: {embedding_service.dimensions}")
    print()
    
    # Create pipeline
    print("2. Creating RAG pipeline...")
    pipeline = ComplianceRAGPipeline(
        persist_dir=rag_data_dir,
        embedding_provider=embedding_provider,
        embedding_model=embedding_model,
        api_key=api_key if not use_local else None
    )
    print(f"   Persist directory: {rag_data_dir}")
    print()
    
    # Index documents
    print("3. Indexing compliance documents...")
    
    # Index controls
    controls_path = frameworks_dir / "soc2" / "controls.yaml"
    if controls_path.exists():
        count = await pipeline.index_controls(controls_path, force_reindex=True)
        print(f"   Indexed {count} control chunks")
    else:
        print(f"   WARNING: {controls_path} not found")
    
    # Index scoring rubric
    rubric_path = frameworks_dir / "soc2" / "scoring_rubric.yaml"
    if rubric_path.exists():
        count = await pipeline.index_scoring_rubric(rubric_path, force_reindex=True)
        print(f"   Indexed {count} rubric chunks")
    else:
        print(f"   WARNING: {rubric_path} not found")
    
    # Index evidence manifest if exists
    manifest_path = evidence_dir / "manifest.json"
    if manifest_path.exists():
        count = await pipeline.index_evidence_manifest(manifest_path, force_reindex=True)
        print(f"   Indexed {count} evidence chunks")
    else:
        print(f"   No evidence manifest found (this is OK for demo)")
    
    print()
    
    # Get stats
    print("4. Pipeline statistics:")
    stats = pipeline.get_stats()
    for collection_name, collection_stats in stats.get("collections", {}).items():
        if isinstance(collection_stats, dict) and "document_count" in collection_stats:
            print(f"   {collection_name}: {collection_stats['document_count']} documents")
    print()
    
    # Demo: Search for control
    print("5. Demo: Searching for 'access control policy MFA'...")
    results = await pipeline.vector_store.search(
        query="access control policy MFA authentication",
        collection_name="controls",
        n_results=3
    )
    
    print(f"   Found {len(results)} results:")
    for i, result in enumerate(results, 1):
        print(f"\n   Result {i} (score: {result.score:.3f}):")
        print(f"   Controls: {result.control_ids}")
        preview = result.content[:200].replace('\n', ' ')
        print(f"   Preview: {preview}...")
    print()
    
    # Demo: Retrieve context for specific control
    print("6. Demo: Retrieving context for CC6.1...")
    context = await pipeline.retrieve_for_control(
        control_id="CC6.1",
        include_rubric=True
    )
    
    print(f"   Retrieved {context.total_chunks} chunks:")
    print(f"   - Control chunks: {len(context.control_chunks)}")
    print(f"   - Evidence chunks: {len(context.evidence_chunks)}")
    print(f"   - Rubric chunks: {len(context.rubric_chunks)}")
    print(f"   Evidence IDs in context: {context.get_evidence_ids()}")
    print()
    
    # Demo: Search for anti-hallucination rules
    print("7. Demo: Retrieving anti-hallucination rules...")
    rules = await pipeline.retrieve_anti_hallucination_rules()
    
    print(f"   Found {len(rules)} rule chunks:")
    for rule in rules[:3]:
        preview = rule.content[:150].replace('\n', ' ')
        print(f"   - {preview}...")
    print()
    
    # Demo: Build assessment prompt
    print("8. Demo: Building assessment prompt for CC6.1...")
    prompt = pipeline.build_assessment_prompt(
        control_id="CC6.1",
        context=context,
        evidence_summary="Evidence CC6.1-E1-001.pdf collected on 2024-03-15 from policy repository."
    )
    
    print("   Prompt preview (first 500 chars):")
    print("   " + "-" * 50)
    print("   " + prompt[:500].replace('\n', '\n   '))
    print("   ...")
    print("   " + "-" * 50)
    print()
    
    # Demo: Hybrid search
    print("9. Demo: Hybrid search for 'evidence required compliance'...")
    hybrid_results = await pipeline.vector_store.hybrid_search(
        query="evidence required compliance assessment",
        collection_name="rubrics",
        n_results=3,
        keyword_weight=0.3
    )
    
    print(f"   Found {len(hybrid_results)} results:")
    for i, result in enumerate(hybrid_results, 1):
        preview = result.content[:100].replace('\n', ' ')
        print(f"   {i}. (score: {result.score:.3f}) {preview}...")
    print()
    
    print("=" * 60)
    print("Demo complete!")
    print()
    print("Next steps:")
    print("1. Add evidence documents to evidence/raw/")
    print("2. Run the compliance checker with RAG context")
    print("3. Integrate with LLM for automated assessments")
    print("=" * 60)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="RAG Pipeline Demo")
    parser.add_argument(
        "--local",
        action="store_true",
        help="Use local embeddings instead of OpenAI"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output"
    )
    
    args = parser.parse_args()
    
    asyncio.run(main(use_local=args.local, verbose=args.verbose))
