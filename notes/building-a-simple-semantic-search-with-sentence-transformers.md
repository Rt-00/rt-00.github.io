---
layout: page
title: "Building a simple semantic search with Sentence Transformers"
permalink: /building-a-simple-semantic-search-with-sentence-transformers/
date: 2025-07-15
---

# Building a simple semantic search with Sentence Transformers (EN-US)

> In this article, I'will explore the core ideas behind **semantic search** using **text embeddings** and **cosine similarity**.

---

## What is Semantic Search?

Traditional search engines match exact words or characters. But semantic search goes deeper, it finds results based on **meaning**, not just matching words.

For example:
- Query: `"puppy"`
- Expected match: `"dog"` (even though they are different words)

How do we make that happen? With embeddings and **similarity metrics**.

---

## What are embeddings?

An **embedding** is a continuous vector representation of text. These vectors are positioned in a high-dimensional space where **semantic similarity** corresponds to **geometric proximity**.

Example:
```
"dog"   → [0.12, 0.45, -0.22, ..., 0.07]
"puppy" → [0.11, 0.44, -0.20, ..., 0.06]
"car"   → [0.77, -0.12, 0.98, ..., -0.33]
```

To generate these vectors, i use a **pre-trained transformer model** like `all-MiniLM-L6-v2`, which maps input text to semantically meaningful vectors.

---
## Cosine Similarity

Once we have embeddings, we compare them using **cosine similarity**, defined as:

<pre>
similarity = (A · B) / (||A|| · ||B||)

Where:
- A . B is the dot product
- ||A|| and ||B|| are vector norms (magnitudes)
</pre>
    
This metric measures the **angle** between vectors — not their magnitude.

- `1.0`: Perfect semantic match
- `0.0`: Orthogonal (unrelated concepts)
- `< 0`: Opposing meaning

---

## The Python Code

```python
from typing import List, Tuple
from sentence_transformers import SentenceTransformers
import numpy as np
from sklearn.metrics.pairwise import consine_similarity

# load a pre-trained model for encoding text into semantic vectors
print("Loading model...")
model = SentenceTransformer("all-MiniLM-L6-v2")
print("Model loaded.")

# our example "database" of know texts
texts = ["dog", "cat", "car"]
print("\nOriginal texts in database:", texts)

# Convert each text into a vector embedding using the model
# normalize_embeddings=True ensures each vector has unit length (norm = 1)
print("\nGenerating embeddings for known texts...")
embeddings = model.encode(texts, normalize_embeddings=True)

# Show the embeddings (first 5 dimensions only for brevity)
for text, vector in zip(texts, embeddings):
    print(f"{text} → {vector[:5]}... (dim={len(vector)})")

# Combine texts and their corresponding embeddings into a list of tuples
database = list(zip(texts, embeddings))

# The user query we want to find the closest match for
query_text = "puppy"
print(f"Query text: '{query_text}'")

# Generate the vector embedding for the query
query_embedding = model.encode([query_text], normalize_embeddings=True)
print(f"Query vector (first 5 dims): {query_embedding[0][:5]}...")

# Function to compute cosine similarity
def find_most_similar(
    query_vec: np.ndarray, database: List[Tuple[str, np.ndarray]]
) -> List[Tuple[str, float]]:
    """
    Finds the most semantically similar texts in the database based on the   cosine similarity.
    """
    vectors = np.array([vec for _, vec in database])
    similarities = cosine_similarity(query_vec, vectors)[0]
    results = [(text, sim) for (text, _), sim in zip(database, similarities)]
    results.sort(key=lambda x: x[1], reverse=True)
    return results

print("\nRunning similarity search...")
results = find_most_similar(query_embedding, database)

print("\nResults:")
for text, similarity in results:
    print(f"→ {text} (cosine similarity: {similarity:.4f})")
```

## Output:

```
Loading model...
Model loaded.

Original texts in database: ['dog', 'cat', 'car']

Generating embeddings for known texts...
dog → [0.04, 0.12, ...]
cat → [0.03, 0.10, ...]
car → [-0.02, 0.08, ...]

Query text: 'puppy'
Query vector (first 5 dims): [0.041, 0.119, 0.075, 0.033, -0.012]...

Running similarity search...

Results:
→ dog (cosine similarity: 0.9103)
→ cat (cosine similarity: 0.7102)
→ car (cosine similarity: 0.3104)
```

## Why use this?

- Great for **search engines**, **chatbots**, **recommendation systems**, etc.
- Doesn't rely on exact word match.
- Works across **synonyms** and **language variation**.

---

# Construindo uma Busca Semântica com Sentence Transformers (PT-BR)

> Neste artigo, vamos explorar os fundamentos por trás da **busca semântica** usando **vetores de embeddings** e **similaridade de cosseno**.

## O que é Busca Semântica?

Buscas tradicionais se baseiam em **casamento exato de palavras-chave**. A **busca semântica**, por outro lado, foca em recuperar resultados com base no **significado**, mesmo que palavras diferentes sejam usadas.

Exemplo:
- Consulta: `"filhote"`
- Resultado esperado: `"cachorro"` (mesmo conceito, palavras diferentes)

Para isso, representamos textos com **vetores de embeddings** — vetores numéricos que capturam o significado da sentença.

---

## O que são Embeddings?

Um **embedding** é uma representação vetorial densa de um texto. Em modelos modernos, como transformers, esses vetores são posicionados em um espaço de alta dimensão, onde **proximidade vetorial representa similaridade semântica**.

Exemplo:
```
"cachorro" → [0.12, 0.45, -0.22, ..., 0.07]
"filhote"  → [0.11, 0.44, -0.20, ..., 0.06]
"carro"    → [0.77, -0.12, 0.98, ..., -0.33]
```

Usamos um modelo transformer pré-treinado, como o `all-MiniLM-L6-v2`, para gerar esses vetores diretamente de textos brutos.

---

## Similaridade de Cosseno

Para comparar vetores, usamos a **similaridade de cosseno**, definida por:

<pre>
similaridade = (A · B) / (||A|| · ||B||)

Onde:
- A . B é o produto escalar
- ||A|| e ||B|| são as normas dos vetores
</pre>
    
Essa métrica mede o **ângulo** entre os vetores, ignorando magnitude:

- `1.0`: Significado idêntico
- `0.0`: Conceitos não relacionados
- `< 0`: Significados opostos

## Por que isso importa?

- Ótimo para **mecanismos de busca**, **chatbots**, **sistemas de recomendação**, etc.
- Não depende de correspondência exata de palavras.
- Funciona com **sinônimos** e **variações linguísticas**.
