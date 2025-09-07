# 🔍 RAG Toolkit - Advanced Retrieval-Augmented Generation

## Overview

The RAG (Retrieval-Augmented Generation) Toolkit is a comprehensive document search and context-aware question answering system that provides advanced semantic search capabilities across documents, embedding generation, and intelligent context retrieval.

## Features

- **Semantic Document Search** - Find relevant documents using natural language queries
- **Context-Aware Q&A** - Generate answers based on retrieved document context
- **Text Embedding Generation** - Create vector embeddings for semantic similarity
- **Similarity Search** - Find documents above similarity thresholds
- **Index Building** - Create searchable document indexes
- **Cross-Platform Support** - Python ML libraries when available, JavaScript fallbacks for universal compatibility

## Tool Registration

```typescript
mcp_mcp-god-mode_rag_toolkit
```

## Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `action` | string | Yes | - | RAG action to perform |
| `query` | string | No | - | Search query or question |
| `documents` | string[] | No | - | Array of documents to search |
| `text` | string | No | - | Text to embed or process |
| `top_k` | number | No | 5 | Number of top results to return (1-20) |
| `context_length` | number | No | 1000 | Maximum context length in characters (100-4000) |
| `similarity_threshold` | number | No | 0.7 | Minimum similarity threshold (0-1) |
| `model_name` | string | No | "all-MiniLM-L6-v2" | Embedding model to use |
| `index_path` | string | No | - | Path to save/load document index |
| `answer_model` | string | No | "gpt-3.5-turbo" | Model for answer generation |

## Actions

### 1. Search Documents
Find the most relevant documents for a given query.

```json
{
  "action": "search_documents",
  "query": "cybersecurity best practices",
  "documents": ["Document 1 content...", "Document 2 content..."],
  "top_k": 5
}
```

**Response:**
```json
{
  "success": true,
  "results": [
    {
      "document": "Document content...",
      "score": 0.85,
      "index": 0
    }
  ],
  "query": "cybersecurity best practices",
  "total_documents": 2
}
```

### 2. Query with Context
Generate contextual answers based on retrieved documents.

```json
{
  "action": "query_with_context",
  "query": "What are the main security vulnerabilities?",
  "documents": ["Security document 1...", "Security document 2..."],
  "context_length": 1500
}
```

**Response:**
```json
{
  "success": true,
  "answer": "Based on the provided context...",
  "context": ["Relevant document excerpts..."],
  "context_length": 1200,
  "documents_used": 3
}
```

### 3. Embed Text
Generate vector embeddings for text.

```json
{
  "action": "embed_text",
  "text": "This is sample text for embedding",
  "model_name": "all-MiniLM-L6-v2"
}
```

**Response:**
```json
{
  "success": true,
  "embedding": [0.1, 0.2, 0.3, ...],
  "dimension": 384,
  "text_length": 35
}
```

### 4. Similarity Search
Find documents above a similarity threshold.

```json
{
  "action": "similarity_search",
  "query": "network security",
  "documents": ["Document 1...", "Document 2..."],
  "top_k": 3,
  "similarity_threshold": 0.8
}
```

**Response:**
```json
{
  "success": true,
  "results": [
    {
      "document": "Network security best practices...",
      "score": 0.92,
      "index": 1
    }
  ],
  "threshold": 0.8,
  "total_above_threshold": 1
}
```

### 5. Build Index
Create a searchable index from documents.

```json
{
  "action": "build_index",
  "documents": ["Document 1...", "Document 2..."],
  "model_name": "all-MiniLM-L6-v2"
}
```

**Response:**
```json
{
  "success": true,
  "index_size": 2,
  "embedding_dimension": 384,
  "model_used": "all-MiniLM-L6-v2"
}
```

### 6. Retrieve Context
Get relevant context for a query.

```json
{
  "action": "retrieve_context",
  "query": "What is penetration testing?",
  "documents": ["Security guide...", "Testing manual..."],
  "context_length": 1000
}
```

**Response:**
```json
{
  "success": true,
  "context": ["Relevant context excerpts..."],
  "context_length": 950,
  "documents_used": 2,
  "similarities": [0.89, 0.76]
}
```

### 7. Generate Answer
Create comprehensive answers using document context.

```json
{
  "action": "generate_answer",
  "query": "How to secure a network?",
  "documents": ["Network security guide...", "Best practices..."],
  "context_length": 2000,
  "answer_model": "gpt-3.5-turbo"
}
```

**Response:**
```json
{
  "success": true,
  "answer": "**Answer to: How to secure a network?**\n\nBased on analysis of 3 relevant documents...",
  "context": ["Context excerpts..."],
  "context_length": 1800,
  "documents_used": 3,
  "model_used": "gpt-3.5-turbo"
}
```

## Implementation Details

### Python Implementation (Preferred)
When Python with required ML libraries is available:
- Uses `sentence-transformers` for embeddings
- Uses `scikit-learn` for similarity calculations
- Supports advanced models like `all-MiniLM-L6-v2`
- Provides high-quality semantic search

### JavaScript Fallback
When Python is not available:
- Uses Jaccard similarity and TF-IDF-like scoring
- Provides basic semantic search capabilities
- Ensures universal compatibility
- Maintains core functionality

## Use Cases

### 1. Document Search
```bash
# Search through security documentation
python -m mcp_god_mode.tools.ai.rag_toolkit \
  --action "search_documents" \
  --query "vulnerability assessment" \
  --documents "['Security guide content...', 'Assessment manual...']" \
  --top_k 5
```

### 2. Knowledge Base Q&A
```bash
# Answer questions using document context
python -m mcp_god_mode.tools.ai.rag_toolkit \
  --action "query_with_context" \
  --query "What are the steps for incident response?" \
  --documents "['Incident response guide...', 'Security procedures...']" \
  --context_length 2000
```

### 3. Content Similarity Analysis
```bash
# Find similar content
python -m mcp_god_mode.tools.ai.rag_toolkit \
  --action "similarity_search" \
  --query "network monitoring" \
  --documents "['Network docs...', 'Monitoring guides...']" \
  --similarity_threshold 0.8
```

## Platform Compatibility

| Platform | Python Support | JavaScript Fallback | Status |
|----------|----------------|-------------------|---------|
| **Windows** | ✅ Full | ✅ Full | **100%** |
| **Linux** | ✅ Full | ✅ Full | **100%** |
| **macOS** | ✅ Full | ✅ Full | **100%** |
| **Android** | ⚠️ Limited | ✅ Full | **95%** |
| **iOS** | ❌ None | ✅ Full | **90%** |

## Dependencies

### Python Dependencies (Optional)
```bash
pip install sentence-transformers scikit-learn numpy
```

### JavaScript Dependencies (Built-in)
- No additional dependencies required
- Uses native JavaScript functionality

## Performance

- **Python Implementation**: High-quality semantic search with advanced ML models
- **JavaScript Fallback**: Fast text processing with basic similarity matching
- **Memory Usage**: Efficient embedding storage and retrieval
- **Speed**: Optimized for real-time document search

## Security Considerations

- **Input Validation**: All inputs are sanitized and validated
- **Memory Management**: Efficient handling of large document collections
- **Error Handling**: Graceful fallback between Python and JavaScript implementations
- **Data Privacy**: No external API calls, all processing is local

## Examples

### Security Documentation Search
```json
{
  "action": "search_documents",
  "query": "OWASP top 10 vulnerabilities",
  "documents": [
    "The OWASP Top 10 is a standard awareness document for developers and web application security...",
    "Cross-Site Scripting (XSS) attacks are a type of injection attack...",
    "SQL injection is a code injection technique used to attack data-driven applications..."
  ],
  "top_k": 3
}
```

### Technical Q&A
```json
{
  "action": "generate_answer",
  "query": "How do I implement secure authentication?",
  "documents": [
    "Authentication is the process of verifying the identity of a user...",
    "Multi-factor authentication (MFA) adds an extra layer of security...",
    "Password policies should enforce strong password requirements..."
  ],
  "context_length": 1500
}
```

## Troubleshooting

### Common Issues

1. **Python Dependencies Missing**
   - Install required packages: `pip install sentence-transformers scikit-learn numpy`
   - Tool will automatically fallback to JavaScript implementation

2. **Low Similarity Scores**
   - Adjust `similarity_threshold` parameter
   - Ensure documents are relevant to the query
   - Try different embedding models

3. **Context Length Issues**
   - Increase `context_length` for longer responses
   - Reduce `top_k` for more focused results

### Performance Tips

- Use appropriate `top_k` values (3-10 for most use cases)
- Set reasonable `context_length` limits (1000-3000 characters)
- Choose suitable `similarity_threshold` values (0.6-0.8)
- Consider document preprocessing for better results

## Related Tools

- **Text Processor** - Advanced text processing and analysis
- **Data Analysis** - Statistical analysis and machine learning
- **Machine Learning** - AI-powered analysis and model training
- **File Operations** - Document loading and management

---

*Last Updated: January 2025*  
*RAG Toolkit v1.6d - Advanced Retrieval-Augmented Generation for MCP God Mode*
