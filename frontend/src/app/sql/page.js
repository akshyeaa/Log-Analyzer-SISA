"use client";
import { useState, useRef } from "react";
import { useRouter } from "next/navigation";

export default function SQLAnalyzer() {
  const [query, setQuery] = useState("");
  const [file, setFile] = useState(null);
  const [result, setResult] = useState(null);

  const inputRef = useRef(null);
  const router = useRouter();

  const handleAnalyze = async () => {
    if (!query && !file) return alert("Add SQL input");

    const formData = new FormData();

    if (file) {
      const text = await file.text();
      formData.append("query", text);
    } else {
      formData.append("query", query);
    }

    const res = await fetch("https://log-analyzer-sisa.onrender.com/analyze-sql", {
      method: "POST",
      body: formData,
    });

    const data = await res.json();
    setResult(data);
  };

  return (
    <div className="min-h-screen text-white p-6 font-mono">

      <button
        onClick={() => router.push("/")}
        className="mb-4 bg-white/10 px-4 py-1 rounded"
      >
        ← Back
      </button>

      <h1 className="text-center text-3xl">
        SQL Security Analyzer
      </h1>

      {!query && (
        <div
          onClick={() => inputRef.current.click()}
          onDrop={(e) => {
            e.preventDefault();
            setFile(e.dataTransfer.files[0]);
          }}
          onDragOver={(e) => e.preventDefault()}
          className="border-2 border-dashed border-white/30 p-8 py-12 rounded-xl text-center cursor-pointer bg-white/2 hover:bg-white/5 my-4 font-mono text-sm"
        >
          Drag & Drop SQL file or Click
          <input
            ref={inputRef}
            type="file"
            className="hidden"
            onChange={(e) => setFile(e.target.files[0])}
          />
        </div>
      )}

      {!file && (
        <textarea
          rows={6}
          placeholder="Paste SQL queries..."
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          className="w-full p-4 bg-black/40 border border-white/10 rounded mb-4"
        />
      )}

      {file && (
        <div className="mb-4">
          Selected: {file.name}
          <button onClick={() => setFile(null)} className="ml-2 text-xs">
            ❌
          </button>
        </div>
      )}

      <div className="text-center">
        <button
          onClick={handleAnalyze}
          className="bg-white text-black px-6 py-2 rounded hover:bg-white/95 hover:font-bold"
        >
          Analyze
        </button>
      </div>

      {result && !result.error && (
        <div className="mt-6 space-y-4">

          <div className="bg-white/10 p-4 rounded">
            <h2 className="text-lg">Summary</h2>
            <p className="text-sm">{result.summary}</p>
          </div>

          <div className="bg-white/10 p-4 rounded">
            <h3 className="">Findings</h3>
            {(result.findings || []).map((f, i) => (
              <p className="text-sm" key={i}>
                {f.type} → {f.value} ({f.risk})
              </p>
            ))}
          </div>

          {/*  BASIC INSIGHTS */}
          <div className="bg-white/10 p-4 rounded">
            <h3 className="text-lg">Insights</h3>
            {(result.insights?.basic || []).map((i, idx) => (
              <p className="text-sm" key={idx}>• {i}</p>
            ))}
          </div>

          {/*  AI INSIGHTS (ADDED CLEANLY) */}
          {result.insights?.ai?.length > 0 && (
            <div className="bg-white/10 p-4 rounded border border-white/20">
              <h3 className="text-lg">AI Insights</h3>
              {result.insights.ai.map((i, idx) => (
                <p key={idx} className="whitespace-pre-line text-sm">{i}</p>
              ))}
            </div>
          )}

        </div>
      )}
    </div>
  );
}