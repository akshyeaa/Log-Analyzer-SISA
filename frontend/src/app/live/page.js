"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";

export default function LiveChat() {
  const [input, setInput] = useState("");
  const [result, setResult] = useState(null);
  const router = useRouter();

  const handleAnalyze = async () => {
    if (!input) return alert("Enter some text");

    const formData = new FormData();
    formData.append("text", input);

    const res = await fetch("https://log-analyzer-sisa.onrender.com/analyze-text", {
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

      <h1 className="text-center text-3xl mb-8">
        Live Chat Security Analyzer
      </h1>

      <textarea
        rows={6}
        placeholder="Paste logs / chat here..."
        value={input}
        onChange={(e) => setInput(e.target.value)}
        className="w-full p-4 bg-black/40 border border-white/10 rounded mb-4"
      />

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
            <h3 className="text-lg">Findings</h3>
            {(result.findings || []).map((f, i) => (
              <p className="text-sm" key={i}>
                {f.type} → {f.value} ({f.risk})
              </p>
            ))}
          </div>

          <div className="bg-white/10 p-4 rounded">
            <h3 className="text-lg">Insights</h3>
            {(result.insights?.basic || []).map((i, idx) => (
              <p className="text-sm" key={idx}>• {i}</p>
            ))}
          </div>

          {/*  AI INSIGHTS */}
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