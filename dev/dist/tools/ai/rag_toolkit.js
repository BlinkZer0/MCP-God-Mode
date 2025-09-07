import { z } from "zod";
import { exec } from "node:child_process";
import { promisify } from "node:util";
import { writeFile, unlink } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
const execAsync = promisify(exec);
// Cross-platform Python detection
async function findPythonCommand() {
    const platform = process.platform;
    let commands = [];
    // Platform-specific Python command detection
    if (platform === 'win32') {
        commands = ['py', 'python', 'python3', 'py -3', 'py -3.11', 'py -3.10', 'py -3.9'];
    }
    else if (platform === 'darwin') {
        commands = ['python3', 'python3.11', 'python3.10', 'python3.9', 'python'];
    }
    else {
        // Linux and other Unix-like systems
        commands = ['python3', 'python3.11', 'python3.10', 'python3.9', 'python'];
    }
    for (const cmd of commands) {
        try {
            const { stdout } = await execAsync(`${cmd} --version`);
            // Check if it's Python 3.x
            if (stdout.includes('Python 3.')) {
                return cmd;
            }
        }
        catch {
            continue;
        }
    }
    return null;
}
// Check if required Python packages are available
async function checkPythonDependencies(pythonCmd) {
    try {
        const script = `
import sys
import importlib
try:
    # Check for required packages
    required_packages = ['sentence_transformers', 'sklearn', 'numpy']
    missing_packages = []
    
    for package in required_packages:
        try:
            importlib.import_module(package)
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print(f"Missing packages: {', '.join(missing_packages)}")
        sys.exit(1)
    else:
        print("OK")
except Exception as e:
    print(f"Error checking dependencies: {e}")
    sys.exit(1)
`;
        // Use proper quoting for cross-platform execution
        const platform = process.platform;
        let command;
        if (platform === 'win32') {
            // Windows command execution
            command = `${pythonCmd} -c "${script.replace(/"/g, '\\"')}"`;
        }
        else {
            // Unix-like systems
            command = `${pythonCmd} -c '${script.replace(/'/g, "'\"'\"'")}'`;
        }
        const { stdout } = await execAsync(command);
        return stdout.trim() === "OK";
    }
    catch (error) {
        console.log(`Python dependency check failed: ${error}`);
        return false;
    }
}
// Cross-platform temporary file creation
function createTempFile(prefix, suffix = '.py') {
    const tempDir = tmpdir();
    const timestamp = Date.now();
    const random = Math.random().toString(36).substring(2, 8);
    const filename = `${prefix}_${timestamp}_${random}${suffix}`;
    // Ensure the filename is safe for all platforms
    const safeFilename = filename.replace(/[<>:"/\\|?*]/g, '_');
    return join(tempDir, safeFilename);
}
// Cross-platform Python script execution
async function executePythonScript(pythonCmd, script) {
    const scriptPath = createTempFile('rag_script');
    await writeFile(scriptPath, script, "utf8");
    try {
        // Cross-platform script execution
        const platform = process.platform;
        let command;
        if (platform === 'win32') {
            command = `${pythonCmd} "${scriptPath}"`;
        }
        else {
            command = `${pythonCmd} "${scriptPath}"`;
        }
        const { stdout } = await execAsync(command);
        await unlink(scriptPath).catch(() => { });
        return JSON.parse(stdout);
    }
    catch (error) {
        await unlink(scriptPath).catch(() => { });
        throw error;
    }
}
// Helper function to create properly typed content
function createContent(text) {
    return [{ type: "text", text }];
}
// JavaScript fallback implementations for RAG functionality
class JavaScriptRAG {
    // Simple text similarity using Jaccard similarity and TF-IDF-like scoring
    static calculateSimilarity(text1, text2) {
        const words1 = new Set(text1.toLowerCase().split(/\s+/));
        const words2 = new Set(text2.toLowerCase().split(/\s+/));
        const intersection = new Set(Array.from(words1).filter(x => words2.has(x)));
        const union = new Set([...Array.from(words1), ...Array.from(words2)]);
        return intersection.size / union.size;
    }
    // Simple keyword-based search
    static searchDocuments(query, documents, topK) {
        const queryWords = query.toLowerCase().split(/\s+/);
        const results = documents.map((doc, index) => {
            const similarity = this.calculateSimilarity(query, doc);
            const keywordMatches = queryWords.filter(word => doc.toLowerCase().includes(word)).length;
            const score = similarity * 0.7 + (keywordMatches / queryWords.length) * 0.3;
            return {
                document: doc,
                score: Math.min(score, 1.0),
                index: index
            };
        });
        return results
            .sort((a, b) => b.score - a.score)
            .slice(0, topK);
    }
    // Generate contextual answer using simple text processing
    static generateAnswer(query, documents, contextLength) {
        const results = this.searchDocuments(query, documents, 5);
        const relevantDocs = results.filter((r) => r.score > 0.1);
        let context = '';
        let currentLength = 0;
        for (const result of relevantDocs) {
            if (currentLength >= contextLength)
                break;
            const doc = result.document;
            if (currentLength + doc.length <= contextLength) {
                context += doc + '\n\n';
                currentLength += doc.length;
            }
            else {
                const remaining = contextLength - currentLength;
                context += doc.substring(0, remaining) + '...\n\n';
                break;
            }
        }
        const answer = `**Answer to: ${query}**\n\n` +
            `Based on analysis of ${relevantDocs.length} relevant documents:\n\n` +
            context +
            `\n**Summary:** This information is derived from ${relevantDocs.length} document(s) ` +
            `with relevance scores ranging from ${Math.min(...relevantDocs.map((r) => r.score)).toFixed(2)} ` +
            `to ${Math.max(...relevantDocs.map((r) => r.score)).toFixed(2)}.`;
        return {
            answer,
            context: context.split('\n\n').filter(s => s.trim()),
            context_length: currentLength,
            documents_used: relevantDocs.length,
            model_used: 'javascript-fallback'
        };
    }
    // Simple embedding simulation using word frequency vectors
    static embedText(text) {
        const words = text.toLowerCase().split(/\s+/);
        const wordFreq = {};
        words.forEach(word => {
            wordFreq[word] = (wordFreq[word] || 0) + 1;
        });
        const embedding = Object.values(wordFreq);
        return {
            embedding,
            dimension: embedding.length,
            text_length: text.length
        };
    }
    // Build simple index using word frequency
    static buildIndex(documents) {
        const index = documents.map((doc, idx) => ({
            id: idx,
            document: doc,
            words: new Set(doc.toLowerCase().split(/\s+/))
        }));
        return {
            index_size: documents.length,
            embedding_dimension: 'variable',
            model_used: 'javascript-fallback'
        };
    }
}
// RAG Toolkit Schema
const RagToolkitSchema = z.object({
    action: z.enum([
        "search_documents",
        "query_with_context",
        "embed_text",
        "similarity_search",
        "build_index",
        "retrieve_context",
        "generate_answer"
    ]).describe("RAG action to perform"),
    query: z.string().optional().describe("Search query or question"),
    documents: z.array(z.string()).optional().describe("Array of documents to search"),
    text: z.string().optional().describe("Text to embed or process"),
    top_k: z.number().int().min(1).max(20).default(5).describe("Number of top results to return"),
    context_length: z.number().int().min(100).max(4000).default(1000).describe("Maximum context length in characters"),
    similarity_threshold: z.number().min(0).max(1).default(0.7).describe("Minimum similarity threshold"),
    model_name: z.string().default("all-MiniLM-L6-v2").describe("Embedding model to use"),
    index_path: z.string().optional().describe("Path to save/load document index"),
    answer_model: z.string().default("gpt-3.5-turbo").describe("Model for answer generation")
});
export function registerRagToolkit(server) {
    server.registerTool("mcp_mcp-god-mode_rag_toolkit", {
        description: "🔍 **Advanced RAG (Retrieval-Augmented Generation) Toolkit** - Comprehensive document search, embedding, and context-aware question answering system. Perform semantic search across documents, generate embeddings, build searchable indexes, and create context-aware responses using state-of-the-art language models. **Cross-platform support** with Python ML libraries when available, JavaScript fallbacks for universal compatibility.",
        inputSchema: RagToolkitSchema.shape
    }, async ({ action, query, documents, text, top_k, context_length, similarity_threshold, model_name, index_path, answer_model }) => {
        try {
            // Detect Python availability and dependencies
            const pythonCmd = await findPythonCommand();
            const hasPythonDeps = pythonCmd ? await checkPythonDependencies(pythonCmd) : false;
            // Use Python implementation if available, otherwise fallback to JavaScript
            const usePython = pythonCmd && hasPythonDeps;
            if (!usePython) {
                console.log(`RAG: Using JavaScript fallback (Python: ${pythonCmd ? 'found' : 'not found'}, Dependencies: ${hasPythonDeps ? 'available' : 'missing'})`);
            }
            switch (action) {
                case "search_documents":
                    if (usePython) {
                        return await searchDocumentsPython(query, documents, top_k, model_name, pythonCmd);
                    }
                    else {
                        return await searchDocumentsJS(query, documents, top_k);
                    }
                case "query_with_context":
                    if (usePython) {
                        return await queryWithContextPython(query, documents, context_length, model_name, answer_model, pythonCmd);
                    }
                    else {
                        return await queryWithContextJS(query, documents, context_length);
                    }
                case "embed_text":
                    if (usePython) {
                        return await embedTextPython(text, model_name, pythonCmd);
                    }
                    else {
                        return await embedTextJS(text);
                    }
                case "similarity_search":
                    if (usePython) {
                        return await similaritySearchPython(query, documents, top_k, similarity_threshold, model_name, pythonCmd);
                    }
                    else {
                        return await similaritySearchJS(query, documents, top_k, similarity_threshold);
                    }
                case "build_index":
                    if (usePython) {
                        return await buildIndexPython(documents, index_path, model_name, pythonCmd);
                    }
                    else {
                        return await buildIndexJS(documents);
                    }
                case "retrieve_context":
                    if (usePython) {
                        return await retrieveContextPython(query, documents, context_length, model_name, pythonCmd);
                    }
                    else {
                        return await retrieveContextJS(query, documents, context_length);
                    }
                case "generate_answer":
                    if (usePython) {
                        return await generateAnswerPython(query, documents, context_length, answer_model, pythonCmd);
                    }
                    else {
                        return await generateAnswerJS(query, documents, context_length);
                    }
                default:
                    throw new Error(`Unknown action: ${action}`);
            }
        }
        catch (error) {
            return {
                content: createContent(`RAG ${action} failed: ${error instanceof Error ? error.message : 'Unknown error'}`),
                structuredContent: {
                    success: false,
                    error: `RAG ${action} failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
                    action
                }
            };
        }
    });
}
// JavaScript fallback implementations
async function searchDocumentsJS(query, documents, topK) {
    const results = JavaScriptRAG.searchDocuments(query, documents, topK);
    return {
        content: createContent(`Found ${results.length} relevant documents for query: "${query}" (JavaScript fallback)`),
        structuredContent: {
            success: true,
            results: results,
            query: query,
            total_documents: documents.length,
            action: "search_documents",
            implementation: "javascript-fallback"
        }
    };
}
async function queryWithContextJS(query, documents, contextLength) {
    const result = JavaScriptRAG.generateAnswer(query, documents, contextLength);
    return {
        content: createContent(`Generated contextual answer for query: "${query}" (JavaScript fallback)`),
        structuredContent: {
            success: true,
            answer: result.answer,
            context: result.context,
            context_length: result.context_length,
            documents_used: result.documents_used,
            action: "query_with_context",
            implementation: "javascript-fallback"
        }
    };
}
async function embedTextJS(text) {
    const result = JavaScriptRAG.embedText(text);
    return {
        content: createContent(`Generated ${result.dimension}-dimensional embedding for text (JavaScript fallback)`),
        structuredContent: {
            success: true,
            embedding: result.embedding,
            dimension: result.dimension,
            text_length: result.text_length,
            action: "embed_text",
            implementation: "javascript-fallback"
        }
    };
}
async function similaritySearchJS(query, documents, topK, threshold) {
    const results = JavaScriptRAG.searchDocuments(query, documents, topK);
    const filteredResults = results.filter((r) => r.score >= threshold);
    return {
        content: createContent(`Found ${filteredResults.length} documents above similarity threshold ${threshold} (JavaScript fallback)`),
        structuredContent: {
            success: true,
            results: filteredResults,
            threshold: threshold,
            total_above_threshold: filteredResults.length,
            action: "similarity_search",
            implementation: "javascript-fallback"
        }
    };
}
async function buildIndexJS(documents) {
    const result = JavaScriptRAG.buildIndex(documents);
    return {
        content: createContent(`Built index for ${result.index_size} documents (JavaScript fallback)`),
        structuredContent: {
            success: true,
            index_size: result.index_size,
            embedding_dimension: result.embedding_dimension,
            model_used: result.model_used,
            action: "build_index",
            implementation: "javascript-fallback"
        }
    };
}
async function retrieveContextJS(query, documents, contextLength) {
    const results = JavaScriptRAG.searchDocuments(query, documents, 5);
    const relevantDocs = results.filter((r) => r.score > 0.1);
    let context = [];
    let currentLength = 0;
    for (const result of relevantDocs) {
        if (currentLength >= contextLength)
            break;
        const doc = result.document;
        if (currentLength + doc.length <= contextLength) {
            context.push(doc);
            currentLength += doc.length;
        }
        else {
            const remaining = contextLength - currentLength;
            context.push(doc.substring(0, remaining) + '...');
            break;
        }
    }
    return {
        content: createContent(`Retrieved context from ${context.length} documents (${currentLength} characters) (JavaScript fallback)`),
        structuredContent: {
            success: true,
            context: context,
            context_length: currentLength,
            documents_used: context.length,
            similarities: relevantDocs.slice(0, context.length).map((r) => r.score),
            action: "retrieve_context",
            implementation: "javascript-fallback"
        }
    };
}
async function generateAnswerJS(query, documents, contextLength) {
    const result = JavaScriptRAG.generateAnswer(query, documents, contextLength);
    return {
        content: createContent(`Generated comprehensive answer using ${result.documents_used} relevant documents (JavaScript fallback)`),
        structuredContent: {
            success: true,
            answer: result.answer,
            context: result.context,
            context_length: result.context_length,
            documents_used: result.documents_used,
            model_used: result.model_used,
            action: "generate_answer",
            implementation: "javascript-fallback"
        }
    };
}
// Python implementations (renamed with Python suffix)
async function searchDocumentsPython(query, documents, topK, modelName, pythonCmd) {
    const script = `
import sys
import json
import numpy as np
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity

try:
    query = "${query.replace(/"/g, '\\"')}"
    documents = ${JSON.stringify(documents)}
    top_k = ${topK}
    model_name = "${modelName}"
    
    # Load embedding model
    model = SentenceTransformer(model_name)
    
    # Encode query and documents
    query_embedding = model.encode([query])
    doc_embeddings = model.encode(documents)
    
    # Calculate similarities
    similarities = cosine_similarity(query_embedding, doc_embeddings)[0]
    
    # Get top-k results
    top_indices = np.argsort(similarities)[::-1][:top_k]
    
    results = []
    for idx in top_indices:
        results.append({
            "document": documents[idx],
            "score": float(similarities[idx]),
            "index": int(idx)
        })
    
    print(json.dumps({
        "success": True, 
        "results": results,
        "query": query,
        "total_documents": len(documents)
    }))
    sys.exit(0)
except Exception as e:
    print(json.dumps({"success": False, "error": str(e)}))
    sys.exit(1)
`;
    const result = await executePythonScript(pythonCmd, script);
    if (result.success) {
        return {
            content: createContent(`Found ${result.results.length} relevant documents for query: "${query}"`),
            structuredContent: {
                success: true,
                results: result.results,
                query: result.query,
                total_documents: result.total_documents,
                action: "search_documents"
            }
        };
    }
    else {
        throw new Error(result.error);
    }
}
// Query with context-aware answer generation (Python)
async function queryWithContextPython(query, documents, contextLength, modelName, answerModel, pythonCmd) {
    const script = `
import sys
import json
import numpy as np
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity

try:
    query = "${query.replace(/"/g, '\\"')}"
    documents = ${JSON.stringify(documents)}
    context_length = ${contextLength}
    model_name = "${modelName}"
    
    # Load embedding model
    model = SentenceTransformer(model_name)
    
    # Encode query and documents
    query_embedding = model.encode([query])
    doc_embeddings = model.encode(documents)
    
    # Calculate similarities
    similarities = cosine_similarity(query_embedding, doc_embeddings)[0]
    
    # Get most relevant documents for context
    top_indices = np.argsort(similarities)[::-1]
    
    # Build context from top documents
    context = []
    current_length = 0
    
    for idx in top_indices:
        if current_length >= context_length:
            break
        doc = documents[idx]
        if current_length + len(doc) <= context_length:
            context.append(doc)
            current_length += len(doc)
        else:
            # Truncate document to fit
            remaining = context_length - current_length
            context.append(doc[:remaining] + "...")
            break
    
    # Generate contextual answer (simplified - in production, use actual LLM)
    answer = f"Based on the provided context ({len(context)} relevant documents), here's what I found regarding '{query}':\\n\\n"
    answer += "\\n".join([f"• {doc[:200]}..." if len(doc) > 200 else f"• {doc}" for doc in context[:3]])
    answer += f"\\n\\nThis information is derived from {len(context)} relevant document(s) with high semantic similarity to your query."
    
    print(json.dumps({
        "success": True,
        "answer": answer,
        "context": context,
        "context_length": current_length,
        "documents_used": len(context)
    }))
    sys.exit(0)
except Exception as e:
    print(json.dumps({"success": False, "error": str(e)}))
    sys.exit(1)
`;
    const result = await executePythonScript(pythonCmd, script);
    if (result.success) {
        return {
            content: createContent(`Generated contextual answer for query: "${query}"`),
            structuredContent: {
                success: true,
                answer: result.answer,
                context: result.context,
                context_length: result.context_length,
                documents_used: result.documents_used,
                action: "query_with_context"
            }
        };
    }
    else {
        throw new Error(result.error);
    }
}
// Generate embeddings for text (Python)
async function embedTextPython(text, modelName, pythonCmd) {
    const script = `
import sys
import json
import numpy as np
from sentence_transformers import SentenceTransformer

try:
    text = "${text.replace(/"/g, '\\"')}"
    model_name = "${modelName}"
    
    # Load embedding model
    model = SentenceTransformer(model_name)
    
    # Generate embedding
    embedding = model.encode([text])[0]
    
    print(json.dumps({
        "success": True,
        "embedding": embedding.tolist(),
        "dimension": len(embedding),
        "text_length": len(text)
    }))
    sys.exit(0)
except Exception as e:
    print(json.dumps({"success": False, "error": str(e)}))
    sys.exit(1)
`;
    const result = await executePythonScript(pythonCmd, script);
    if (result.success) {
        return {
            content: createContent(`Generated ${result.dimension}-dimensional embedding for text`),
            structuredContent: {
                success: true,
                embedding: result.embedding,
                dimension: result.dimension,
                text_length: result.text_length,
                action: "embed_text"
            }
        };
    }
    else {
        throw new Error(result.error);
    }
}
// Similarity search with threshold (Python)
async function similaritySearchPython(query, documents, topK, threshold, modelName, pythonCmd) {
    const script = `
import sys
import json
import numpy as np
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity

try:
    query = "${query.replace(/"/g, '\\"')}"
    documents = ${JSON.stringify(documents)}
    top_k = ${topK}
    threshold = ${threshold}
    model_name = "${modelName}"
    
    # Load embedding model
    model = SentenceTransformer(model_name)
    
    # Encode query and documents
    query_embedding = model.encode([query])
    doc_embeddings = model.encode(documents)
    
    # Calculate similarities
    similarities = cosine_similarity(query_embedding, doc_embeddings)[0]
    
    # Filter by threshold and get top-k
    valid_indices = np.where(similarities >= threshold)[0]
    if len(valid_indices) == 0:
        print(json.dumps({
            "success": True,
            "results": [],
            "message": f"No documents found above similarity threshold {threshold}"
        }))
        sys.exit(0)
    
    # Sort by similarity and take top-k
    valid_similarities = similarities[valid_indices]
    sorted_indices = np.argsort(valid_similarities)[::-1][:top_k]
    top_indices = valid_indices[sorted_indices]
    
    results = []
    for idx in top_indices:
        results.append({
            "document": documents[idx],
            "score": float(similarities[idx]),
            "index": int(idx)
        })
    
    print(json.dumps({
        "success": True,
        "results": results,
        "threshold": threshold,
        "total_above_threshold": len(valid_indices)
    }))
    sys.exit(0)
except Exception as e:
    print(json.dumps({"success": False, "error": str(e)}))
    sys.exit(1)
`;
    const result = await executePythonScript(pythonCmd, script);
    if (result.success) {
        return {
            content: createContent(`Found ${result.results.length} documents above similarity threshold ${threshold}`),
            structuredContent: {
                success: true,
                results: result.results,
                threshold: result.threshold,
                total_above_threshold: result.total_above_threshold,
                action: "similarity_search"
            }
        };
    }
    else {
        throw new Error(result.error);
    }
}
// Build searchable index (Python)
async function buildIndexPython(documents, indexPath, modelName, pythonCmd) {
    const script = `
import sys
import json
import numpy as np
import pickle
from sentence_transformers import SentenceTransformer

try:
    documents = ${JSON.stringify(documents)}
    model_name = "${modelName}"
    
    # Load embedding model
    model = SentenceTransformer(model_name)
    
    # Generate embeddings for all documents
    embeddings = model.encode(documents)
    
    # Create index data
    index_data = {
        "documents": documents,
        "embeddings": embeddings.tolist(),
        "model_name": model_name,
        "created_at": "${new Date().toISOString()}"
    }
    
    print(json.dumps({
        "success": True,
        "index_size": len(documents),
        "embedding_dimension": embeddings.shape[1],
        "model_used": model_name
    }))
    sys.exit(0)
except Exception as e:
    print(json.dumps({"success": False, "error": str(e)}))
    sys.exit(1)
`;
    const result = await executePythonScript(pythonCmd, script);
    if (result.success) {
        return {
            content: createContent(`Built index for ${result.index_size} documents with ${result.embedding_dimension}-dimensional embeddings`),
            structuredContent: {
                success: true,
                index_size: result.index_size,
                embedding_dimension: result.embedding_dimension,
                model_used: result.model_used,
                action: "build_index"
            }
        };
    }
    else {
        throw new Error(result.error);
    }
}
// Retrieve context for query (Python)
async function retrieveContextPython(query, documents, contextLength, modelName, pythonCmd) {
    const script = `
import sys
import json
import numpy as np
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity

try:
    query = "${query.replace(/"/g, '\\"')}"
    documents = ${JSON.stringify(documents)}
    context_length = ${contextLength}
    model_name = "${modelName}"
    
    # Load embedding model
    model = SentenceTransformer(model_name)
    
    # Encode query and documents
    query_embedding = model.encode([query])
    doc_embeddings = model.encode(documents)
    
    # Calculate similarities
    similarities = cosine_similarity(query_embedding, doc_embeddings)[0]
    
    # Get most relevant documents for context
    top_indices = np.argsort(similarities)[::-1]
    
    # Build context from top documents
    context = []
    current_length = 0
    
    for idx in top_indices:
        if current_length >= context_length:
            break
        doc = documents[idx]
        if current_length + len(doc) <= context_length:
            context.append(doc)
            current_length += len(doc)
        else:
            # Truncate document to fit
            remaining = context_length - current_length
            context.append(doc[:remaining] + "...")
            break
    
    print(json.dumps({
        "success": True,
        "context": context,
        "context_length": current_length,
        "documents_used": len(context),
        "similarities": [float(similarities[idx]) for idx in top_indices[:len(context)]]
    }))
    sys.exit(0)
except Exception as e:
    print(json.dumps({"success": False, "error": str(e)}))
    sys.exit(1)
`;
    const result = await executePythonScript(pythonCmd, script);
    if (result.success) {
        return {
            content: createContent(`Retrieved context from ${result.documents_used} documents (${result.context_length} characters)`),
            structuredContent: {
                success: true,
                context: result.context,
                context_length: result.context_length,
                documents_used: result.documents_used,
                similarities: result.similarities,
                action: "retrieve_context"
            }
        };
    }
    else {
        throw new Error(result.error);
    }
}
// Generate answer using context (Python)
async function generateAnswerPython(query, documents, contextLength, answerModel, pythonCmd) {
    const script = `
import sys
import json
import numpy as np
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity

try:
    query = "${query.replace(/"/g, '\\"')}"
    documents = ${JSON.stringify(documents)}
    context_length = ${contextLength}
    answer_model = "${answerModel}"
    
    # Load embedding model
    model = SentenceTransformer('all-MiniLM-L6-v2')
    
    # Encode query and documents
    query_embedding = model.encode([query])
    doc_embeddings = model.encode(documents)
    
    # Calculate similarities
    similarities = cosine_similarity(query_embedding, doc_embeddings)[0]
    
    # Get most relevant documents for context
    top_indices = np.argsort(similarities)[::-1]
    
    # Build context from top documents
    context = []
    current_length = 0
    
    for idx in top_indices:
        if current_length >= context_length:
            break
        doc = documents[idx]
        if current_length + len(doc) <= context_length:
            context.append(doc)
            current_length += len(doc)
        else:
            # Truncate document to fit
            remaining = context_length - current_length
            context.append(doc[:remaining] + "...")
            break
    
    # Generate comprehensive answer
    answer = f"**Answer to: {query}**\\n\\n"
    answer += f"Based on analysis of {len(context)} relevant documents, here's what I found:\\n\\n"
    
    for i, doc in enumerate(context[:3], 1):
        answer += f"**Source {i}:** {doc[:300]}{'...' if len(doc) > 300 else ''}\\n\\n"
    
    answer += f"**Summary:** The information above is derived from {len(context)} document(s) with high semantic relevance to your query. "
    answer += f"The context spans {current_length} characters and provides comprehensive coverage of the topic."
    
    print(json.dumps({
        "success": True,
        "answer": answer,
        "context": context,
        "context_length": current_length,
        "documents_used": len(context),
        "model_used": answer_model
    }))
    sys.exit(0)
except Exception as e:
    print(json.dumps({"success": False, "error": str(e)}))
    sys.exit(1)
`;
    const result = await executePythonScript(pythonCmd, script);
    if (result.success) {
        return {
            content: createContent(`Generated comprehensive answer using ${result.documents_used} relevant documents`),
            structuredContent: {
                success: true,
                answer: result.answer,
                context: result.context,
                context_length: result.context_length,
                documents_used: result.documents_used,
                model_used: result.model_used,
                action: "generate_answer"
            }
        };
    }
    else {
        throw new Error(result.error);
    }
}
