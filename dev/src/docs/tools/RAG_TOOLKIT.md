# RAG Toolkit Documentation

## Overview

The **RAG (Retrieval-Augmented Generation) Toolkit** is a comprehensive document search, embedding, and context-aware question answering system. It provides advanced semantic search capabilities across documents, generates embeddings, builds searchable indexes, and creates context-aware responses using state-of-the-art language models.

## Features

- **Semantic Document Search**: Find relevant documents using semantic similarity
- **Context-Aware Q&A**: Generate answers based on retrieved context
- **Text Embedding**: Generate vector embeddings for text
- **Similarity Search**: Find similar content with configurable thresholds
- **Index Building**: Create searchable document indexes
- **Context Retrieval**: Extract relevant context for queries
- **Answer Generation**: Generate comprehensive answers using retrieved context

## Tool Name

`mcp_mcp-god-mode_rag_toolkit`

## Parameters

### Required Parameters

- **action** (enum): The RAG action to perform
  - `search_documents`: Search documents using semantic similarity
  - `query_with_context`: Query with context-aware answer generation
  - `embed_text`: Generate embeddings for text
  - `similarity_search`: Similarity search with threshold
  - `build_index`: Build searchable index
  - `retrieve_context`: Retrieve context for query
  - `generate_answer`: Generate answer using context

### Optional Parameters

- **query** (string): Search query or question
- **documents** (array of strings): Array of documents to search
- **text** (string): Text to embed or process
- **top_k** (number): Number of top results to return (default: 5, max: 20)
- **context_length** (number): Maximum context length in characters (default: 1000, max: 4000)
- **similarity_threshold** (number): Minimum similarity threshold (default: 0.7, range: 0-1)
- **model_name** (string): Embedding model to use (default: "all-MiniLM-L6-v2")
- **index_path** (string): Path to save/load document index
- **answer_model** (string): Model for answer generation (default: "gpt-3.5-turbo")

## Usage Examples

### 1. Search Documents

```javascript
{
  "action": "search_documents",
  "query": "machine learning algorithms",
  "documents": [
    "Machine learning is a subset of artificial intelligence...",
    "Deep learning uses neural networks with multiple layers...",
    "Natural language processing helps computers understand text..."
  ],
  "top_k": 3
}
```

### 2. Query with Context

```javascript
{
  "action": "query_with_context",
  "query": "What are the benefits of machine learning?",
  "documents": [
    "Machine learning improves efficiency and accuracy...",
    "ML algorithms can process large datasets quickly...",
    "Automated decision making reduces human error..."
  ],
  "context_length": 1500
}
```

### 3. Generate Text Embeddings

```javascript
{
  "action": "embed_text",
  "text": "This is a sample text for embedding generation",
  "model_name": "all-MiniLM-L6-v2"
}
```

### 4. Similarity Search

```javascript
{
  "action": "similarity_search",
  "query": "artificial intelligence",
  "documents": [
    "AI is transforming industries worldwide...",
    "Machine learning is a key component of AI...",
    "Natural language processing enables AI communication..."
  ],
  "similarity_threshold": 0.8,
  "top_k": 5
}
```

### 5. Build Document Index

```javascript
{
  "action": "build_index",
  "documents": [
    "Document 1 content...",
    "Document 2 content...",
    "Document 3 content..."
  ],
  "index_path": "./document_index.json",
  "model_name": "all-MiniLM-L6-v2"
}
```

### 6. Retrieve Context

```javascript
{
  "action": "retrieve_context",
  "query": "security best practices",
  "documents": [
    "Use strong passwords and two-factor authentication...",
    "Keep software updated and patched regularly...",
    "Implement network segmentation and monitoring..."
  ],
  "context_length": 2000
}
```

### 7. Generate Answer

```javascript
{
  "action": "generate_answer",
  "query": "How do I secure my network?",
  "documents": [
    "Network security involves multiple layers of protection...",
    "Firewalls, intrusion detection, and monitoring are essential...",
    "Regular security audits and updates are crucial..."
  ],
  "context_length": 1500,
  "answer_model": "gpt-3.5-turbo"
}
```

## Return Format

All RAG toolkit operations return a structured response with:

```javascript
{
  "content": [
    {
      "type": "text",
      "text": "Operation completed successfully"
    }
  ],
  "structuredContent": {
    "success": true,
    "action": "search_documents",
    // Action-specific data
    "results": [...], // For search operations
    "answer": "...", // For answer generation
    "context": [...], // For context operations
    "embedding": [...], // For embedding operations
    // Additional fields based on action
  }
}
```

## Technical Implementation

### Dependencies

- **Python**: Required for embedding generation
- **sentence-transformers**: For text embeddings
- **scikit-learn**: For similarity calculations
- **numpy**: For numerical operations

### Models Used

- **Default Embedding Model**: `all-MiniLM-L6-v2`
  - Lightweight and efficient
  - Good performance for most use cases
  - 384-dimensional embeddings

### Performance Considerations

- **Document Size**: Large documents are automatically truncated to fit context length
- **Batch Processing**: Multiple documents are processed efficiently
- **Memory Usage**: Embeddings are generated on-demand to minimize memory usage
- **Caching**: Consider implementing caching for frequently accessed documents

## Error Handling

The RAG toolkit includes comprehensive error handling:

- **Missing Dependencies**: Clear error messages for missing Python packages
- **Invalid Parameters**: Validation of input parameters
- **Processing Errors**: Graceful handling of embedding generation failures
- **Timeout Protection**: Automatic cleanup of temporary files

## Security Considerations

- **Input Validation**: All inputs are validated and sanitized
- **Temporary Files**: Scripts are automatically cleaned up after execution
- **Error Messages**: Sensitive information is not exposed in error messages
- **Resource Limits**: Built-in limits prevent resource exhaustion

## Integration

The RAG toolkit is integrated into both:

- **Server-Refactored**: Available in the comprehensive server
- **Modular System**: Available as a standalone module

## Use Cases

1. **Document Search**: Find relevant information in large document collections
2. **Question Answering**: Answer questions based on document content
3. **Content Recommendation**: Suggest similar content based on semantic similarity
4. **Knowledge Base**: Build and query knowledge bases
5. **Research Assistance**: Help researchers find relevant papers and information
6. **Customer Support**: Provide context-aware responses to customer queries

## Best Practices

1. **Document Preprocessing**: Clean and normalize documents before processing
2. **Context Length**: Choose appropriate context length based on your use case
3. **Similarity Threshold**: Adjust threshold based on desired precision/recall
4. **Model Selection**: Choose embedding models based on your domain and requirements
5. **Index Management**: Regularly update indexes for dynamic document collections

## Troubleshooting

### Common Issues

1. **Python Not Found**: Ensure Python is installed and accessible
2. **Missing Dependencies**: Install required Python packages
3. **Memory Issues**: Reduce document size or batch size
4. **Slow Performance**: Consider using smaller embedding models

### Performance Optimization

1. **Batch Processing**: Process multiple documents together
2. **Model Caching**: Cache embedding models for reuse
3. **Index Precomputation**: Precompute indexes for frequently accessed documents
4. **Parallel Processing**: Use multiple processes for large document collections

## Future Enhancements

- **Custom Models**: Support for custom embedding models
- **Vector Databases**: Integration with vector databases for large-scale search
- **Multi-language Support**: Support for multiple languages
- **Real-time Updates**: Real-time index updates for dynamic content
- **Advanced Filtering**: More sophisticated filtering and ranking options
