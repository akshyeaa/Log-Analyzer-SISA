"use client";
import { useState, useRef } from "react";
import { useRouter } from "next/navigation";

export default function Home() {
  const [files, setFiles] = useState([]);
  const [results, setResults] = useState([]);
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [currentFinding, setCurrentFinding] = useState(0);

  const inputRef = useRef(null);
  const router = useRouter();

  const handleUpload = async () => {
    if (files.length === 0) {
      alert("Please upload files first");
      return;
    }

    const formData = new FormData();
    files.forEach((f) => formData.append("files", f));

    const res = await fetch("https://log-analyzer-sisa.onrender.com/analyze", {
      method: "POST",
      body: formData,
    });

    const data = await res.json();
    setResults(data.results);
  };

  const selected = results[selectedIndex];

  // AI FORMAT
  const formatAI = (text) => {
    if (!text) return null;

    const sections = text.split(/SUMMARY:|ANOMALIES:|RISKS:/);

    return (
      <div className="space-y-3 text-sm font-mono">
        {text.includes("SUMMARY") && (
          <div>
            <p className="font-bold text-green-300 text-lg">SUMMARY</p>
            {sections[1]?.split("-").map((s, i) =>
              s.trim() && <p key={i}>• {s.trim()}</p>
            )}
          </div>
        )}

        {text.includes("ANOMALIES") && (
          <div>
            <p className="font-bold text-yellow-300 text-lg">ANOMALIES</p>
            {sections[2]?.split("-").map((s, i) =>
              s.trim() && <p key={i}>• {s.trim()}</p>
            )}
          </div>
        )}

        {text.includes("RISKS") && (
          <div>
            <p className="font-bold text-red-300 text-lg">RISKS</p>
            {sections[3]?.split("-").map((s, i) =>
              s.trim() && <p key={i}>• {s.trim()}</p>
            )}
          </div>
        )}
      </div>
    );
  };

  //  HIGHLIGHT 
  const renderLines = (text, findings) => {
    const lines = text.split("\n");

    return lines.map((line, i) => {
      const lineFindings = findings.filter((f) => f.line === i + 1);

      let highlightedLine = line;

      lineFindings.forEach((f) => {
        const color =
          f.risk === "critical"
            ? "bg-red-600 text-white"
            : f.risk === "high"
            ? "bg-orange-400 text-black"
            : "bg-yellow-300 text-black";

        const escaped = f.value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        const regex = new RegExp(escaped, "g");

        highlightedLine = highlightedLine.replace(
          regex,
          `<span class="${color} px-1 rounded">${f.value}</span>`
        );
      });

      let bg = "";
      if (lineFindings.some((f) => f.risk === "critical")) bg = "bg-red-500/20";
      else if (lineFindings.some((f) => f.risk === "high")) bg = "bg-orange-400/20";
      else if (lineFindings.length > 0) bg = "bg-yellow-300/20";

      return (
        <div key={i} id={`line-${i}`} className={`flex px-2 py-1 ${bg}`}>
          <span className="w-10 text-gray-500 text-right mr-3 text-sm">{i + 1}</span>
          <span
            className="flex-1 whitespace-pre-wrap text-sm font-mono"
            dangerouslySetInnerHTML={{ __html: highlightedLine }}
          />
        </div>
      );
    });
  };

  const removeFile = (index) => {
    const newFiles = [...files];
    newFiles.splice(index, 1);
    setFiles(newFiles);
  };

  const removeResult = (index) => {
    const newResults = [...results];
    newResults.splice(index, 1);
    setResults(newResults);
    setSelectedIndex(0);
  };

  const nextFinding = () => {
    if (!selected) return;
    const next = (currentFinding + 1) % selected.findings.length;
    setCurrentFinding(next);
    document.getElementById(`line-${selected.findings[next].line - 1}`)?.scrollIntoView({ behavior: "smooth", block: "center" });
  };

  const prevFinding = () => {
    if (!selected) return;
    const prev = (currentFinding - 1 + selected.findings.length) % selected.findings.length;
    setCurrentFinding(prev);
    document.getElementById(`line-${selected.findings[prev].line - 1}`)?.scrollIntoView({ behavior: "smooth", block: "center" });
  };

  return (
    <div className="min-h-screen flex text-white">

      {/* Sidebar */}
      {sidebarOpen && (
        <div className="w-72 p-4 bg-white/5 backdrop-blur border-r border-white/10 flex flex-col justify-between">

          <div>
            <h2 className="text-center font-bold mb-4 mt-5 font-mono text-lg">FILES</h2>

            <div className="space-y-3">
              {results.map((f, i) => (
                <div
                  key={i}
                  className="relative p-3 rounded-2xl cursor-pointer text-center border border-white/10 transition-all hover:bg-white/10"
                >
                  <div onClick={() => setSelectedIndex(i)} className="font-mono text-sm">
                    {f.file_name}
                  </div>

                  {/* CENTERED ❌ */}
                  <button
                    onClick={() => removeResult(i)}
                    className="absolute right-2 top-1/2 -translate-y-1/2 text-xs"
                  >
                    ❌
                  </button>
                </div>
              ))}
            </div>
          </div>

          {/* NEW BUTTONS */}
          <div className="space-y-2 mt-6">
            <button
              onClick={() => router.push("/live")}
              className="w-full bg-white/10 hover:bg-white/20 py-2 rounded font-mono text-sm"
            >
              Live Chat
            </button>

            <button
              onClick={() => router.push("/sql")}
              className="w-full bg-white/10 hover:bg-white/20 py-2 rounded font-mono text-sm"
            >
              SQL Analyzer
            </button>
          </div>
        </div>
      )}

      {/* Toggle */}
      <button onClick={() => setSidebarOpen(!sidebarOpen)} className="absolute top-4 left-4 z-50 bg-black/60 px-2 py-1 rounded">
        {sidebarOpen ? "←" : "→"}
      </button>

      {/* Main */}
      <div className="flex-1 p-6 overflow-y-auto">

        <h1 className="text-3xl font-bold text-center mb-6 font-mono">
          Log Security Dashboard
        </h1>

        {/* Upload */}
        <div
          onClick={() => inputRef.current.click()}
          onDrop={(e) => {
            e.preventDefault();
            setFiles([...files, ...Array.from(e.dataTransfer.files)]);
          }}
          onDragOver={(e) => e.preventDefault()}
          className="border-2 border-dashed border-white/30 p-8 py-15 rounded-xl text-center cursor-pointer bg-white/5 hover:bg-white/10 mb-4 font-mono text-sm"
        >
          Drag & Drop files or Click Here
          <input ref={inputRef} type="file" multiple className="hidden"
            onChange={(e) => setFiles([...files, ...Array.from(e.target.files)])}
          />
        </div>

        {/* Preview */}
        {files.length > 0 && (
          <div className="flex flex-wrap gap-2 mb-4 justify-center">
            {files.map((f, i) => (
              <div key={i} className="bg-white/10 px-3 py-1 rounded-full font-mono text-sm">
                {f.name}
                <button onClick={() => removeFile(i)} className="ml-2 text-xs">❌</button>
              </div>
            ))}
          </div>
        )}

        {/* Analyze */}
        <div className="flex justify-center">
          <button onClick={handleUpload} className="bg-white text-black px-6 py-2 rounded-lg font-mono text-sm">
            Analyze Files
          </button>
        </div>

        {/* Results */}
        {selected && (
          <div className="mt-6 space-y-6">

            <div className="bg-white/10 p-4 rounded-xl">
              <h2 className="font-bold font-mono text-lg">{selected.file_name}</h2>
              <p className="font-mono text-sm">{selected.summary}</p>
            </div>

            {/* DROPDOWN */}
            <details className="bg-white/10 p-4 rounded-xl">
              <summary className="cursor-pointer font-bold font-mono text-sm">
                View All Breaches ({selected.findings.length})
              </summary>

              <div className="mt-3 space-y-2">
                {selected.findings.map((f, i) => (
                  <div key={i} className="px-3 py-1 rounded text-sm font-mono">
                    {f.line} → {f.value} ({f.risk})
                  </div>
                ))}
              </div>
            </details>

            {/* Insights */}
            <div className="bg-white/10 p-4 rounded-xl">
              <h3 className="font-bold font-mono text-lg">Insights</h3>
              {selected.insights.basic.map((i, idx) => (
                <p key={idx} className="font-mono text-sm">• {i}</p>
              ))}
            </div>

            {/* AI Insights */}
            {selected.insights.ai.length > 0 && (
              <div className="bg-white/10 p-4 rounded-xl">
                <h3 className="font-bold font-mono text-lg">AI Insights</h3>
                {selected.insights.ai.map((i, idx) => (
                  <div key={idx}>{formatAI(i)}</div>
                ))}
              </div>
            )}

            {/* Navigation */}
            {selected.findings.length > 1 && (
              <div className="flex gap-4 justify-center">
                <button onClick={prevFinding} className="font-mono text-sm">⬆ Prev</button>
                <button onClick={nextFinding} className="font-mono text-sm">⬇ Next</button>
              </div>
            )}

            {/* Logs */}
            <div className="bg-black/70 max-h-[500px] overflow-y-auto rounded-xl border border-white/10 font-mono text-sm">
              {renderLines(selected.text, selected.findings)}
            </div>

          </div>
        )}
      </div>
    </div>
  );
}